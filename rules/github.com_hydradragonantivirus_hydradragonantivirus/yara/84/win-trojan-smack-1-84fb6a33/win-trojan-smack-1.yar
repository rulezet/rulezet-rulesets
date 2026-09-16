rule Win_Trojan_Smack_1
{
strings:
	$a0 = { 4d4bcd217203e92c015e56908bfe33 }


condition:
	$a0
}