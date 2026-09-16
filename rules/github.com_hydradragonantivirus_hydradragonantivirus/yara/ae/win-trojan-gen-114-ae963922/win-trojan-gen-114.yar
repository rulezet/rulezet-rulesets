rule Win_Trojan_Gen_114
{
strings:
	$a0 = { b90070f2aeb90400acae75eee2fa5e07897c1789f783c7 }


condition:
	$a0
}