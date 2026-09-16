rule Win_Trojan_Vegeta_1
{
strings:
	$a0 = { 1a8d5680cd21e816005ab41acd218be533c08bd88bc88b }


condition:
	$a0
}