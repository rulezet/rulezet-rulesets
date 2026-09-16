rule Win_Trojan_Menem_1
{
strings:
	$a0 = { ba0000b943028d9e16002e8b0733da4343e2f7 }


condition:
	$a0
}