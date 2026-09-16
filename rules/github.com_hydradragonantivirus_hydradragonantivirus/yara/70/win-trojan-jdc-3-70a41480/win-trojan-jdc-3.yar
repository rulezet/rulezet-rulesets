rule Win_Trojan_JDC_3
{
strings:
	$a0 = { ff47afaff7244717a8ae8447f781262995ae47afaff7aaa1afff81242995ae4624b73f3f460caf }


condition:
	$a0
}