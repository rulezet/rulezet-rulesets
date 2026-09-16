rule Win_Trojan_DPVG_1
{
strings:
	$a0 = { 44756b652f534d469a000037005589e581ec0001bfa6010e57bf52001e57b8ff00509aa208 }


condition:
	$a0
}