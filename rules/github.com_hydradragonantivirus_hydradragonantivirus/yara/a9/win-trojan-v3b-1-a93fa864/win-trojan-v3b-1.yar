rule Win_Trojan_V3b_1
{
strings:
	$a0 = { ffcd2181fb110775298c060c00c7060a00b900b44ccd }


condition:
	$a0
}