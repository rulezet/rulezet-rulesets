rule Win_Trojan_Trojan_351
{
strings:
	$a0 = { 01b9a4012e812f523883c302e2f6 }


condition:
	$a0
}