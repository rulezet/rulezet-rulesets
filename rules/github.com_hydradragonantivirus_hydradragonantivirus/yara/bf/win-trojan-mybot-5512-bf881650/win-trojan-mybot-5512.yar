rule Win_Trojan_Mybot_5512
{
strings:
	$a0 = { 3aeb7be13cf59af247a85d466c2ca8ee9b04192cdb8d50a4f69ecf5f5ddceb4cc3de12ce0d4922bfa325195ab9cd8da6301810ea4a848cba94ae3caa1a70947fcfb970fd4ebe }


condition:
	$a0
}