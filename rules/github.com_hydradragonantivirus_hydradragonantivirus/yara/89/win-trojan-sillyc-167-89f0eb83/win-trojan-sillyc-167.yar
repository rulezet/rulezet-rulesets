rule Win_Trojan_SillyC_167
{
strings:
	$a0 = { 3402890e3602b440b904008d962a02cd21b8024233c933d2cd21b43080c410b932018d960001 }


condition:
	$a0
}