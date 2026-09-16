rule Win_Trojan_VCC_35
{
strings:
	$a0 = { 2802e82a00b440b92c018d960501cd21e81c00b800422bc999cd21b440b904008d96b501cd21 }


condition:
	$a0
}