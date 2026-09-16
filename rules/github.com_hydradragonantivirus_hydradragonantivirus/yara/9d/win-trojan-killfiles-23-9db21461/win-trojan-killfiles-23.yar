rule Win_Trojan_KillFiles_23
{
strings:
	$a0 = { 6563686f206f6666400d0a5c63640d0a2a2e2a2044656c74726565205c79 }


condition:
	$a0
}