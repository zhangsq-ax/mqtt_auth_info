package mqtt_auth_info

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// 连接协议
type ConnectionProtocol string

const (
	ConnectionProtocolTcp ConnectionProtocol = "tcp" // 端口 1883
	ConnectionProtocolSsl ConnectionProtocol = "ssl" // 端口 8883
	ConnectionProtocolWs  ConnectionProtocol = "ws"  // 端口 80
	ConnectionProtocolWss ConnectionProtocol = "wss" // 端口 443
)

var ConnectionPort = map[ConnectionProtocol]int{
	ConnectionProtocolTcp: 1883,
	ConnectionProtocolSsl: 8883,
	ConnectionProtocolWs:  80,
	ConnectionProtocolWss: 443,
}

// 鉴权模式
type AuthType string

const (
	AuthTypeSign   AuthType = "Signature"        // 签名鉴权模式
	AuthTypeToken  AuthType = "Token"            // Token 鉴权模式
	AuthTypeDevice AuthType = "DeviceCredential" // 一机一密鉴权模式
)

type TokenInfo struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

type MQTTAuthInfo struct {
	Protocol    ConnectionProtocol // 连接协议
	InstanceID  string             // 服务实例标识
	Host        string             // 服务接入点
	Port        int                // 服务接入点端口
	AccessKeyID string             // 签名和 Token 模式下为管理员分配的 AccessKeyId , 一机一密模式下为鉴权服务分发的 DeviceAccessKeyId
	Secret      string             // 签名鉴权模式下使用管理员分发的 AccessKeySecret； Token 鉴权模式下使用鉴权服务分发的 Token；一机一密鉴权模式下使用鉴权服务分发的 DeviceAccessKeySecret
	GroupID     string
	ClientID    string
}

func (a *MQTTAuthInfo) GetClient(authType AuthType, onConnect mqtt.OnConnectHandler, onConnectionLost mqtt.ConnectionLostHandler) mqtt.Client {
	connectOpts := a.GetConnectOptions(authType)
	return getClient(connectOpts, onConnect, onConnectionLost)
}

func UpdateToken(client mqtt.Client, tokenInfo *TokenInfo) error {
	payload, err := json.Marshal(client)
	if err != nil {
		return err
	}
	token := client.Publish("$SYS/uploadToken", 2, false, payload)
	token.Wait()
	err = token.Error()
	return err
}

func (a *MQTTAuthInfo) GetConnectOptions(authType AuthType) *ConnectOptions {
	port := a.standardPort(a.Port)
	clientId := fmt.Sprintf("%s@@@%s", a.GroupID, a.ClientID)
	broker := fmt.Sprintf("%s://%s:%d", a.Protocol, a.Host, port)
	username := fmt.Sprintf("%s|%s|%s", authType, a.AccessKeyID, a.InstanceID)

	var password string
	switch authType {
	case AuthTypeSign, AuthTypeDevice:
		mac := hmac.New(sha1.New, []byte(a.Secret))
		mac.Write([]byte(clientId))
		password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	case AuthTypeToken:
		password = a.Secret
	}

	return &ConnectOptions{
		Username: username,
		Password: password,
		Broker:   broker,
		ClientID: clientId,
	}
}

func (a *MQTTAuthInfo) standardPort(port int) int {
	if port == 0 {
		port = ConnectionPort[a.Protocol]
	}

	return port
}

func getClient(connectOpts *ConnectOptions, onConnect mqtt.OnConnectHandler, onConnectionLost mqtt.ConnectionLostHandler) mqtt.Client {
	//opts := getMQTTClientOptions(connectOpts)
	opts := connectOpts.GetMQTTClientOptions()

	if onConnect == nil {
		opts.OnConnect = func(client mqtt.Client) {
			fmt.Println("---------- Connect to server success ----------")
		}
	} else {
		opts.OnConnect = onConnect
	}

	if onConnectionLost == nil {
		opts.OnConnectionLost = func(client mqtt.Client, err error) {
			fmt.Printf("-----X----- Lost connection with server: %v\n", err)
		}
	} else {
		opts.OnConnectionLost = onConnectionLost
	}

	return mqtt.NewClient(opts)
}

/* func getMQTTClientOptions(connectOpts *ConnectOptions) *mqtt.ClientOptions {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(connectOpts.Broker)
	opts.SetClientID(connectOpts.ClientID)
	opts.SetUsername(connectOpts.Username)
	opts.SetPassword(connectOpts.Password)

	return opts
} */
