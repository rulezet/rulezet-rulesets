rule Win_Trojan_Natas_14
{
strings:
	$a0 = { 81f38b74bdace033d4bf3c23fb4581c70100f9f581de1b27f7db299bfeffe2ec }


condition:
	$a0
}