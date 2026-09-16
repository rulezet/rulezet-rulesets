rule Win_Trojan_DPVG_2
{
strings:
	$a0 = { 44756b652f534d469a00005c005589e581ec0001bf34030e57bf52001e57b8ff00509aa208 }


condition:
	$a0
}