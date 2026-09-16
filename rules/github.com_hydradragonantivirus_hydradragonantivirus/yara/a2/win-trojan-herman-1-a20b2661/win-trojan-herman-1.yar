rule Win_Trojan_Herman_1
{
strings:
	$a0 = { b80040b904008d96f600cd21fe86fa00b802422bc999cd21b440b95e018d960600cd21b43ecd21c3 }


condition:
	$a0
}