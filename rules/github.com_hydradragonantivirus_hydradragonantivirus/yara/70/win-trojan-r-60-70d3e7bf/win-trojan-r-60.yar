rule Win_Trojan_R_60
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb1083e30080e400b0000c0580cc03cd16c38bee33c00d6666cd2181 }


condition:
	$a0
}