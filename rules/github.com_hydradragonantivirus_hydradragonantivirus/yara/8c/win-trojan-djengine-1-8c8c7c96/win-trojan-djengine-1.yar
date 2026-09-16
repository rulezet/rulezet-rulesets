rule Win_Trojan_Djengine_1
{
strings:
	$a0 = { e80000eb01??5e81ee0300[1-25]b93d11fcf3a4 }


condition:
	$a0
}