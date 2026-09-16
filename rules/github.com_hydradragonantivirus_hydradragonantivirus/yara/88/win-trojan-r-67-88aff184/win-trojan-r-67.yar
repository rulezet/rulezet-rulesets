rule Win_Trojan_R_67
{
strings:
	$a0 = { 0156bc0201e80000e80d008b360001bcfeff81ee0901eb09b80503c1e310cd16c38beeb400c0e0080c6680cc66cd2181fb6666746f0e1fb44a6aff5bcd2183eb272a }


condition:
	$a0
}