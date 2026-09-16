rule Win_Trojan_SmallComp_3
{
strings:
	$a0 = { 4b753a60061ebf5c01578bf20e07acaa0ac075fab456 }


condition:
	$a0
}