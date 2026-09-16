rule Win_Trojan_Trivial_236
{
strings:
	$a0 = { b12aba000193cd21b43ecd21b44febdfc3 }


condition:
	$a0
}