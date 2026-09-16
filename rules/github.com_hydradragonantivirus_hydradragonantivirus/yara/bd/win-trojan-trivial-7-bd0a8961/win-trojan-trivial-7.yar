rule Win_Trojan_Trivial_7
{
strings:
	$a0 = { 2a2e2a00b44e8bd6cd21b8013dba9e00cd2193b440ebef }


condition:
	$a0
}