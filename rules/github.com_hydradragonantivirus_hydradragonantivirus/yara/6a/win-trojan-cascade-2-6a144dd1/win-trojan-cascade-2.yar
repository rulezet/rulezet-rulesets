rule Win_Trojan_Cascade_2
{
strings:
	$a0 = { fe4b907507bd3412909dfbcffb9d2eff2e5c05 }


condition:
	$a0
}