rule Win_Trojan_DPOG_3
{
strings:
	$a0 = { 44756b652f534d469a000044005589e581ec0001bf4e020e57bf52001e57b8ff00509aa208 }


condition:
	$a0
}