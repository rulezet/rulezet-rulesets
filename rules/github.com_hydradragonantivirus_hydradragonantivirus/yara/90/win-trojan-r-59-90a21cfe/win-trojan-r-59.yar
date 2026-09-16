rule Win_Trojan_R_59
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0ec1eb10c1e8100c0580cc03cd16c38beeb86666cd2181fb666674 }


condition:
	$a0
}