rule Win_Trojan_Peed_429
{
strings:
	$a0 = { 5383e8620bc62bdf23c64a574b81f2c5c7ecbe2bc781c9bf0ddb1e5681f2c7ce }


condition:
	$a0
}