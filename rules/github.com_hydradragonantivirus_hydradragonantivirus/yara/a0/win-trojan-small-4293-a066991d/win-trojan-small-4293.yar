rule Win_Trojan_Small_4293
{
strings:
	$a0 = { 56575355e8??000000e8[0-30]6a006a006a006a006a }


condition:
	$a0
}