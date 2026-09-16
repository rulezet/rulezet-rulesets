rule Win_Trojan_Tiny_51
{
strings:
	$a0 = { 40b9a0008d960901721bb8004233c933d2cd21b440b904008d969d01cd21b41aba8000cd218db6 }


condition:
	$a0
}