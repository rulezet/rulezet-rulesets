rule Win_Trojan_CyberWarrior_2
{
strings:
	$a0 = { ed1e011e06bf00018db62802b90500f3a4b41a8d964702cd21b44e8d963202b107cd217303e9d4 }


condition:
	$a0
}