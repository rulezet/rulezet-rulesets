rule Win_Trojan_Trivial_91
{
strings:
	$a0 = { 2a00b44e8bd6cd21b43cba9e }


condition:
	$a0
}