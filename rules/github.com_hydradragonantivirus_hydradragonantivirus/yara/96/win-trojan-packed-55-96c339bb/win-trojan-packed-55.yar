rule Win_Trojan_Packed_55
{
strings:
	$a0 = { 60e8060000008b642408eb0c2bd264ff32648922cc02eb }


condition:
	$a0
}