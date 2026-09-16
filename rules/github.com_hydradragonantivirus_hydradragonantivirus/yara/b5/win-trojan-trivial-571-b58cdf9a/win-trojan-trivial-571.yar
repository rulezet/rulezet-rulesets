rule Win_Trojan_Trivial_571
{
strings:
	$a0 = { b8013dcd2193b440ba0001b9????cd21b43ecd21b44fcd2173 }


condition:
	$a0
}