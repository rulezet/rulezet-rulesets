rule Win_Trojan_SomeKit_11
{
strings:
	$a0 = { b80040b904008d96ba00cd21fe86be00b802422bc999cd21b440b91d018d960600cd21b43ecd21c3 }


condition:
	$a0
}