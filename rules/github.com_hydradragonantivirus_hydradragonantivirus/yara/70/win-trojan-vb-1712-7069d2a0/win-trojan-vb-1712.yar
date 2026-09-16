rule Win_Trojan_VB_1712
{
strings:
	$a0 = { 6e766565676865720000000007000000709940 }


condition:
	$a0
}