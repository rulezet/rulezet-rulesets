rule Win_Trojan_Trivial_95
{
strings:
	$a0 = { 2a00b44e8bd6cd21b8013dba9e00cd2193b4408bd6cd21 }


condition:
	$a0
}