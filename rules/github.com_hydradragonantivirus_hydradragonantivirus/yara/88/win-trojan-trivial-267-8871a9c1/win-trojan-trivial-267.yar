rule Win_Trojan_Trivial_267
{
strings:
	$a0 = { ba2601cd21721cb8013dba9e00cd2193b440b12cba0001cd21b43ecd21b44fcd21ebe2c3 }


condition:
	$a0
}