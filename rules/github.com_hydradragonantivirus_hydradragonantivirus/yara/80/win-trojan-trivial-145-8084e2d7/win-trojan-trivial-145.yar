rule Win_Trojan_Trivial_145
{
strings:
	$a0 = { 023dba9e00cd2193b44083cd62baafcd21c32a2e432a00 }


condition:
	$a0
}