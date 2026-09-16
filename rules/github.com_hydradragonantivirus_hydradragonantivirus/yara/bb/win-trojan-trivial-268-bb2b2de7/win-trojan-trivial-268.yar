rule Win_Trojan_Trivial_268
{
strings:
	$a0 = { ba2701cd21721cba9e00b8023dcd2193b4408a0e2c00ba0001cd21b43ecd21b44febe0cd202a2e632a00 }


condition:
	$a0
}