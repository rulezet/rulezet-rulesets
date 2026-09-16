rule Win_Trojan_Lazy_3
{
strings:
	$a0 = { 020055e60000020003000e0300004e010000030000001c03 }


condition:
	$a0
}