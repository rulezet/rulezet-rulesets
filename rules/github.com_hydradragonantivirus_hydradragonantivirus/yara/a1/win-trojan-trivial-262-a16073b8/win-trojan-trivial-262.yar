rule Win_Trojan_Trivial_262
{
strings:
	$a0 = { 2601b44e33c9cd21721aba9e00b8013dcd2193b440b12cba0001cd21b43ecd21b44febe0c32a2e434f4d00 }


condition:
	$a0
}