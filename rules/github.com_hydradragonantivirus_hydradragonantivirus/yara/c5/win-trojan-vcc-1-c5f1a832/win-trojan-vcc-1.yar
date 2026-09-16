rule Win_Trojan_VCC_1
{
strings:
	$a0 = { b904008d96aa00cd21fe86ae00b802422bc999cd21b440b90d018d960600cd21b43ecd21c3 }


condition:
	$a0
}