rule Win_Trojan_Cpw_4
{
strings:
	$a0 = { 5f83ef038bf7f9e80502e9fe000e1f33f633fff8e8 }


condition:
	$a0
}