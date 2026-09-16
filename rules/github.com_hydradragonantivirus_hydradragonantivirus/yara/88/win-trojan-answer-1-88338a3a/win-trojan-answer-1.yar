rule Win_Trojan_Answer_1
{
strings:
	$a0 = { e800005e83ee??56b8ae30cd2181f9c60475 }


condition:
	$a0
}