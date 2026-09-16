rule Win_Trojan_R_64
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb082bdbb80503cd16c38bee2500000d6666cd2181fb6666746b0e1f }


condition:
	$a0
}