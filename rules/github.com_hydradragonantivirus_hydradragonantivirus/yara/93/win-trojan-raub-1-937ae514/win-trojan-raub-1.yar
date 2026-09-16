rule Win_Trojan_Raub_1
{
strings:
	$a0 = { 3f01b41acd21e8d4fbe8c7fb7303e9 }


condition:
	$a0
}