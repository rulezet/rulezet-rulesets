rule Win_Trojan_Peed_428
{
strings:
	$a0 = { 81ea29977a312bce535783cb932bf883e04b81c1061b716956ff150c214000ff }


condition:
	$a0
}