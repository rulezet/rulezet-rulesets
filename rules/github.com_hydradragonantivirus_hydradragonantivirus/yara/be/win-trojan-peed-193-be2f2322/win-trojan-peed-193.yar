rule Win_Trojan_Peed_193
{
strings:
	$a0 = { e8340000005589e56a0152e8130000002b55082b550c03551003551483e90fc9 }


condition:
	$a0
}