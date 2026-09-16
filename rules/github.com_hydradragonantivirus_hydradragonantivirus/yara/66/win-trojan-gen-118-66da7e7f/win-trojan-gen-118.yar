rule Win_Trojan_Gen_118
{
strings:
	$a0 = { 04a184002e89470ba186002e89470d }


condition:
	$a0
}