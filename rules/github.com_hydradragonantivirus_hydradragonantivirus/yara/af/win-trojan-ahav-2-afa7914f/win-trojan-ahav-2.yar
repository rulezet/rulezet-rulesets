rule Win_Trojan_AHAV_2
{
strings:
	$a0 = { 030089862c02b440b97f018d960001cd21b8004233c933d2cd21b440b904008d962b02cd21 }


condition:
	$a0
}