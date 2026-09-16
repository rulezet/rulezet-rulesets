rule Win_Trojan_Quish_3
{
strings:
	$a0 = { 02b440b904008d962902cd21b8024233c933d2cd21b43080c410b931018d960001cd21b800 }


condition:
	$a0
}