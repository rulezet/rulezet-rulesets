rule Win_Trojan_Twister_5
{
strings:
	$a0 = { 4233c933d2cd21b440b904008d96d501cd21b8024233c933d2cd21b440b9ef008d960001cd21 }


condition:
	$a0
}