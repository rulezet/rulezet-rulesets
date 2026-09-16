rule Win_Trojan_Vundo_447
{
strings:
	$a0 = { 558beceb3f57585beb515c58525c575a5d5b545f505452535a575652575e535f51515056555956 }


condition:
	$a0
}