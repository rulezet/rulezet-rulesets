rule Win_Trojan_Sadist_1
{
strings:
	$a0 = { 46100001e80000582dd700b104d3e88ccb03c32d100050 }


condition:
	$a0
}