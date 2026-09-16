rule Win_Trojan_Erase_2
{
strings:
	$a0 = { b95400ba00008ccb8edbbb000050535152cd269d5a595b58c3 }


condition:
	$a0
}