rule Win_Trojan_SillyC_57
{
strings:
	$a0 = { e988a6a001b440b9a2008d960a01cd21721bb8004233c933d2cd21b440b904008d96a001cd21b4 }


condition:
	$a0
}