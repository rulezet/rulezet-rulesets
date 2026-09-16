rule Win_Trojan_Delorado_1
{
strings:
	$a0 = { 444a264f7074696d612647426f747c636f637554657c7879750000 }


condition:
	$a0
}