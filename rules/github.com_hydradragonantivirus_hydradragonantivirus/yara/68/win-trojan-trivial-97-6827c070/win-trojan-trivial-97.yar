rule Win_Trojan_Trivial_97
{
strings:
	$a0 = { 2a2e2a00b44efec6cd21b8023dba9e00cd2193b44087d1cd21 }


condition:
	$a0
}