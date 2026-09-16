rule Win_Trojan_R_69
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0cbb0000b8d100053402cd16c38bee68666658cd2181fb66667470 }


condition:
	$a0
}