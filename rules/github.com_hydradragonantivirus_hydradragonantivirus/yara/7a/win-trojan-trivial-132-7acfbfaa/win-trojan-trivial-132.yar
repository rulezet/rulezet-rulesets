rule Win_Trojan_Trivial_132
{
strings:
	$a0 = { ba1901cd21b8013dba9e00cd2193b440b1ff8bd6cd21c3 }


condition:
	$a0
}