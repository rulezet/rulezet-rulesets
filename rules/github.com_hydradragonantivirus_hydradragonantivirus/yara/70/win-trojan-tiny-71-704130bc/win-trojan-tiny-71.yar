rule Win_Trojan_Tiny_71
{
strings:
	$a0 = { 1202b440b904008d961802cd21b8024233c933d2cd21b440b922018d960001cd21b8002ccd21 }


condition:
	$a0
}