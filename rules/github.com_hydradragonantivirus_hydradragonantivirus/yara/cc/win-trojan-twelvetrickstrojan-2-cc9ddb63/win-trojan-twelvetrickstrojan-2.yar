rule Win_Trojan_TwelveTricksTrojan_2
{
strings:
	$a0 = { bab8dbbe640231944201d1c24e79f733 }


condition:
	$a0
}