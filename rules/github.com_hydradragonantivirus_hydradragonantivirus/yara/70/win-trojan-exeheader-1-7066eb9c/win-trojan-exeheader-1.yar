rule Win_Trojan_ExeHeader_1
{
strings:
	$a0 = { 7c0189f78e0612000e1fb91501f3a4b81325061fba8301cd21b44a0e07bb3900cd210e1f8b1e2c }


condition:
	$a0
}