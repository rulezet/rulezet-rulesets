rule Win_Trojan_UseKill_1
{
strings:
	$a0 = { 21891eff0c8c06010d1e0e1fba7a01b81b25 }


condition:
	$a0
}