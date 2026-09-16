rule Win_Trojan_Majkl_2
{
strings:
	$a0 = { 01bffb2e2e013a464681c7ca5481fe940172f1 }


condition:
	$a0
}