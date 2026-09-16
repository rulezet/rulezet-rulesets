rule Win_Trojan_SomeKit_9
{
strings:
	$a0 = { b80040b904008d96b200cd21fe86b600b802422bc999cd21b440b915018d960600cd21b43ecd21c3 }


condition:
	$a0
}