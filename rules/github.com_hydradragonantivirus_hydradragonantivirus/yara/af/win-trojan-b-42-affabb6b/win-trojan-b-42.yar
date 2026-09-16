rule Win_Trojan_B_42
{
strings:
	$a0 = { 7cc645fe0f894702884df9c7073e7cfbcd1372468b0e137c890e207c }


condition:
	$a0
}