rule Win_Trojan_Oksana_3
{
strings:
	$a0 = { bf3f072bfe8bcf2e8a0434aa2e880446e2f5be0500bfb0022bfe8bcf2e8a0434aa2e880446 }


condition:
	$a0
}