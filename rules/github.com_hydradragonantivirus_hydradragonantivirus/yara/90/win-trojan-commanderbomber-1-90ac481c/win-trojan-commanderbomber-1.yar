rule Win_Trojan_CommanderBomber_1
{
strings:
	$a0 = { ffd1e0962eff940004ebbe2e0460066f068506a306e0 }


condition:
	$a0
}