rule Win_Trojan_SomeKit_8
{
strings:
	$a0 = { 40b904008d96ae00cd21fe86b200b802422bc999cd21b440b911018d960600cd21b43ecd21c3 }


condition:
	$a0
}