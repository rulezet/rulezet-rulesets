rule Win_Trojan_Jakarta_1
{
strings:
	$a0 = { 6bb40a80d4d20d0c9bb9b367f180d411766bb4f680d4760c0d9e9d67f54ce67c80d43e8367f36cb6 }


condition:
	$a0
}