rule Win_Trojan_Coito_1
{
strings:
	$a0 = { bd0000060e07bf150103fdb96f022680350047e2f9 }


condition:
	$a0
}