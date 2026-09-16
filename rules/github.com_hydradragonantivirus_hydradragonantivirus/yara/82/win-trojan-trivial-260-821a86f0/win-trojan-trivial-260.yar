rule Win_Trojan_Trivial_260
{
strings:
	$a0 = { 2601cd21b8013dba9e00cd2193b440b12c9090ba0001cd21b43ecd21b4 }


condition:
	$a0
}