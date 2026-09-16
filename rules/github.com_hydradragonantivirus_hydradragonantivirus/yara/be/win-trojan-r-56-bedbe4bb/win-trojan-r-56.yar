rule Win_Trojan_R_56
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0db403b005c0ef08c0eb08cd16c38bee2ae4c0e8080d6666cd2181 }


condition:
	$a0
}