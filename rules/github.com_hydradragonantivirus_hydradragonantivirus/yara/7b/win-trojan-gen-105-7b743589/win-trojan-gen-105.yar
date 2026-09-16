rule Win_Trojan_Gen_105
{
strings:
	$a0 = { 060e1f1e07bb15002e8037 }


condition:
	$a0
}