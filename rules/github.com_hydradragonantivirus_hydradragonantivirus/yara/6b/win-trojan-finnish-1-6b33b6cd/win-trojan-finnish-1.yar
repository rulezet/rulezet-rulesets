rule Win_Trojan_Finnish_1
{
strings:
	$a0 = { 33c08ec026a18400268b0e86000726a39a }


condition:
	$a0
}