rule Win_Trojan_Trivial_544
{
strings:
	$a0 = { b44eba????cd21[0-2]b8023dba????cd2193b440b12bba0001cd21b43ecd21b44fcd21 }


condition:
	$a0
}