rule Win_Trojan_HI_1
{
strings:
	$a0 = { ed0633c08ed8813e6401d32e7449c7066401d32e8b1613044a89161304b106d3e2b94000 }


condition:
	$a0
}