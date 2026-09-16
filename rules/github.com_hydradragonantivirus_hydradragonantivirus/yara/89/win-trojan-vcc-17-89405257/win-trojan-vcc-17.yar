rule Win_Trojan_VCC_17
{
strings:
	$a0 = { 86b701b440b90e018d960501cd21b800422bc999cd21b440b904008d96b601cd21fe86b201b43e }


condition:
	$a0
}