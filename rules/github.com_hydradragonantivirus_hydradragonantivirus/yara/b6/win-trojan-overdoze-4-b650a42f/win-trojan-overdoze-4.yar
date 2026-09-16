rule Win_Trojan_Overdoze_4
{
strings:
	$a0 = { bc0201e80000e80d008b360001bcfeff81ee0a01eb08b8050333dbcd16c38beeb86666cd2181fb6666745b0e1fb44abbffffcd2183eb1f90b44acd21b448bb1e }


condition:
	$a0
}