rule Win_Trojan_Trivial_402
{
strings:
	$a0 = { 2a00b44e8bd6cd21b8023dba9e00cd2193b440ebef }


condition:
	$a0
}