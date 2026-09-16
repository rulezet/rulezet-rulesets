rule Win_Trojan_Small_4258
{
strings:
	$a0 = { 8d3405000000008d743300[0-120]8145089c0900008d7d088b7c2700c9 }


condition:
	$a0
}