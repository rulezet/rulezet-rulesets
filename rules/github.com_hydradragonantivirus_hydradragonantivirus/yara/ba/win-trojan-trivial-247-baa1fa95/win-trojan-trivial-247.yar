rule Win_Trojan_Trivial_247
{
strings:
	$a0 = { 2501b44ecd21ba9e00b8013dcd2193b440b92a00ba0001cd21b43ecd21b44fcd2173e3c3 }


condition:
	$a0
}