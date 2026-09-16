rule Win_Trojan_Trivial_277
{
strings:
	$a0 = { b44ecd21721dba9e00b8013dcd2193b440b92d00ba0001cd21b43ecd21b44fcd2173e1c3 }


condition:
	$a0
}