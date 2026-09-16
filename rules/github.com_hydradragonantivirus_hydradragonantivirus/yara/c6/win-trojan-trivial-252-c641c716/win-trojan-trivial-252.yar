rule Win_Trojan_Trivial_252
{
strings:
	$a0 = { ba2701cd21b8013dba9e00cd2193b440b12b9090ba0001cd21b43ecd21b44fcd2173e2 }


condition:
	$a0
}