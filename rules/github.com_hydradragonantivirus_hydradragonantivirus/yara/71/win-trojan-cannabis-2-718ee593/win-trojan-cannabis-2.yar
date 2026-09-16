rule Win_Trojan_Cannabis_2
{
strings:
	$a0 = { 8944018bd6b96501902bd1b440cd21b8004233c933d2cd218bd6b90300b440cd218b4c198b }


condition:
	$a0
}