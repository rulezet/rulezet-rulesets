rule Win_Trojan_VCC_2
{
strings:
	$a0 = { b904008d96b401cd21fe86b801b802422bc999cd21b440b945808d960601cd21b43ecd21c3 }


condition:
	$a0
}