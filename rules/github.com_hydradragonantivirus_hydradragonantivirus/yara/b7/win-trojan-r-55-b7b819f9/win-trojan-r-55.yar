rule Win_Trojan_R_55
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0ab403b00583e300cd16c38beeb8e303058362cd2181fb6666746d }


condition:
	$a0
}