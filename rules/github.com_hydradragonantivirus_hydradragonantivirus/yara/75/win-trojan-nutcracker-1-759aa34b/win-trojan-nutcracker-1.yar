rule Win_Trojan_Nutcracker_1
{
strings:
	$a0 = { bc00793232b92c50b400cd138ec4ba0000bb0000b80d02cd1372ea }


condition:
	$a0
}