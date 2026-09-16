rule Win_Trojan_R_54
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0d32e432c00d050383e300cd16c38bee2bc080cc660c66cd2181fb }


condition:
	$a0
}