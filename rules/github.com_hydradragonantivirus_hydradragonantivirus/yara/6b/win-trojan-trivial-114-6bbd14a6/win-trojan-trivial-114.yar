rule Win_Trojan_Trivial_114
{
strings:
	$a0 = { 2a2e2a0051b44e87cacd21b8023dba9e00cd2193b440495acd21c3 }


condition:
	$a0
}