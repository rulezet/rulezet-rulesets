rule Win_Trojan_SomeKit_6
{
strings:
	$a0 = { 40b904008d96a200cd21fe86a600b802422bc999cd21b440b905018d960600cd21b43ecd21c3 }


condition:
	$a0
}