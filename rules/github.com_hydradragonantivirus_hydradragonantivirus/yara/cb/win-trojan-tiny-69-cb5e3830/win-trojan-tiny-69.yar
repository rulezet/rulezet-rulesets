rule Win_Trojan_Tiny_69
{
strings:
	$a0 = { 1102b440b904008d961702cd21b8024233c933d2cd21b440b921018d960001cd21b8002ccd21 }


condition:
	$a0
}