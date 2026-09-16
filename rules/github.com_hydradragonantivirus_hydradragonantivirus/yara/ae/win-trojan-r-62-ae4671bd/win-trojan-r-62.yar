rule Win_Trojan_R_62
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0ab805032aff2adbcd16c38bee2bc00c6680cc66cd2181fb666674 }


condition:
	$a0
}