rule Win_Trojan_VGEN_68
{
strings:
	$a0 = { e988a69f01b440b9a1008d960a01721bb8004233c933d2cd21b440b904008d969f01cd21b41aba }


condition:
	$a0
}