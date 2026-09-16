rule Win_Trojan_SillyC_59
{
strings:
	$a0 = { 40b9a0008d960901cd21721bb8004233c933d2cd21b440b904008d969f01cd21b41aba8000cd21 }


condition:
	$a0
}