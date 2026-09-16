rule Win_Trojan_R_63
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0ec1eb10b8000080cc030c05cd16c38beeb8672c05ff39cd2181fb }


condition:
	$a0
}