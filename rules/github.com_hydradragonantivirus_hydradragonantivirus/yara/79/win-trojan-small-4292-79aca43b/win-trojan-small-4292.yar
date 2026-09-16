rule Win_Trojan_Small_4292
{
strings:
	$a0 = { 5690575355e8??000000e8[0-30]6a006a006a006a006a }


condition:
	$a0
}