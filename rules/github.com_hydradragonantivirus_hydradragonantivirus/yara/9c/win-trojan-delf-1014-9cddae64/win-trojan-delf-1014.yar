rule Win_Trojan_Delf_1014
{
strings:
	$a0 = { e819fbffff84c074698d45e4e881f5ffff8d45e4bad8514000e80ceaffff8b45e4e8fcebffff508b0350e82ff2ffff }


condition:
	$a0
}