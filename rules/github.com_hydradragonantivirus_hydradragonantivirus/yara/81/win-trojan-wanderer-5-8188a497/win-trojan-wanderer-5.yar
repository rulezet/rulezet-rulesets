rule Win_Trojan_Wanderer_5
{
strings:
	$a0 = { e874fdb80042595acd21b440b96a0733d2cd21b800428b16d2078b0ed407cd21b44033c9cd }


condition:
	$a0
}