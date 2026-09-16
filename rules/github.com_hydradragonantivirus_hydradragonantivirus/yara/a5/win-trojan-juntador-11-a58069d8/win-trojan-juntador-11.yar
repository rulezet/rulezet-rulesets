rule Win_Trojan_Juntador_11
{
strings:
	$a0 = { 65786500ffffffff060000005c74656d705c0000ffffffff030000004a554e00ffffffff03000000415f3000ffffffff0e0000006472 }


condition:
	$a0
}