rule Win_Trojan_Quish_2
{
strings:
	$a0 = { 162702890e2902b440b904008d961d02cd21b8024233c933d2cd21b440b925018d960001cd21b8 }


condition:
	$a0
}