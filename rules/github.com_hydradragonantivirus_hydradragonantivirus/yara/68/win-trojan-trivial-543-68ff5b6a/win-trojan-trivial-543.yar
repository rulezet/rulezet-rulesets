rule Win_Trojan_Trivial_543
{
strings:
	$a0 = { b44e33c9cd21[0-5]b8013dcd2193b440b1??565acd21b43ecd21 }


condition:
	$a0
}