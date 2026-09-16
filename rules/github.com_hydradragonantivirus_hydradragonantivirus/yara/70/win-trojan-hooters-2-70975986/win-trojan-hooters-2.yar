rule Win_Trojan_Hooters_2
{
strings:
	$a0 = { 84b17abcbd7e6047820ecccd805200d4414f3c73760f0802eab1834941b16385a7e2d31101 }


condition:
	$a0
}