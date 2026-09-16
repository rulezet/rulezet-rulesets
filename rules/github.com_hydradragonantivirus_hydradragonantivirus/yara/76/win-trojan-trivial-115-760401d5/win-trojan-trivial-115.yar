rule Win_Trojan_Trivial_115
{
strings:
	$a0 = { 1101b44ecd21ba9e00b43dcd2193b21b2a2e432a00000000000199211a }


condition:
	$a0
}