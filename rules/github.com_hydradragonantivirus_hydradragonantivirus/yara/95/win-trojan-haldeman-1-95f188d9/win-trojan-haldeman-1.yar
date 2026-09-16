rule Win_Trojan_Haldeman_1
{
strings:
	$a0 = { b904008d96f100cd21fe86f500b802422bc999cd21b440b955018d960600cd21b43ecd21c3 }


condition:
	$a0
}