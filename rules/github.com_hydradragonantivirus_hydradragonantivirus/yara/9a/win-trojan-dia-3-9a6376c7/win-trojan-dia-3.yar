rule Win_Trojan_Dia_3
{
strings:
	$a0 = { 28666f6c6465722b225c5c74726173686b69647265616c2e68746d2229 }


condition:
	$a0
}