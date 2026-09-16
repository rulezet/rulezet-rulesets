rule Win_Trojan_VCC_3
{
strings:
	$a0 = { 860202b440b909018d960001cd21b800422bc999cd21b440b904008d960102cd21b43ecd21b44f }


condition:
	$a0
}