rule Win_Trojan_Trojan_426
{
strings:
	$a0 = { 01b9????8135????4747e2f8c3 }


condition:
	$a0
}