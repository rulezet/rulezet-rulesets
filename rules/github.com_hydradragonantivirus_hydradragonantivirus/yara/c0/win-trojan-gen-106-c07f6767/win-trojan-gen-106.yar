rule Win_Trojan_Gen_106
{
strings:
	$a0 = { 1fba0001b93c02b800409c2eff1e7d02 }


condition:
	$a0
}