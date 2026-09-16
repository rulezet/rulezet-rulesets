rule Win_Trojan_K_4
{
strings:
	$a0 = { 3400042eff062100902e813e2100571175eb90 }


condition:
	$a0
}