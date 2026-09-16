rule Win_Trojan_VGEN_709
{
strings:
	$a0 = { 0200b9050391bb000090cd16555ef8f8e86307e18f8e51700cc39dd28411f7f05fd8c0a1b2992a51310c519dd2d870 }


condition:
	$a0
}