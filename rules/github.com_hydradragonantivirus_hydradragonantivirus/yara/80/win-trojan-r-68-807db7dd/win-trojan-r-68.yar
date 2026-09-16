rule Win_Trojan_R_68
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0c578bfb2bdf5fb80503cd16c38beeb466b066cd2181fb66667469 }


condition:
	$a0
}