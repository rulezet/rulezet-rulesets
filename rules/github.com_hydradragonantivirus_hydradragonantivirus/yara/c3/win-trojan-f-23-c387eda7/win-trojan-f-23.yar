rule Win_Trojan_F_23
{
strings:
	$a0 = { 32008bfe1e060e1f0e07ada3f9033116f903a1f903abeb0590b44ccd21e2ebfa2e892605 }


condition:
	$a0
}