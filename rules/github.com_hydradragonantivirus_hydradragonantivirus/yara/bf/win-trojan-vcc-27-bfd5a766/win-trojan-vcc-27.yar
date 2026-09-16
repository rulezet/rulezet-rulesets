rule Win_Trojan_VCC_27
{
strings:
	$a0 = { 40b904008d96b001cd21fe86b401b802422bc999cd21b440b91b028d960600cd21b43ecd21c3 }


condition:
	$a0
}