rule Win_Trojan_R_65
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0bc0e7082adbb80503cd16c38beeb466b066cd2181fb666674660e }


condition:
	$a0
}