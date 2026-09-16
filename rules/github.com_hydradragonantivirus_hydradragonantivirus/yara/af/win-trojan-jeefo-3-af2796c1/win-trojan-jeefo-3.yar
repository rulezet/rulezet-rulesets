rule Win_Trojan_Jeefo_3
{
strings:
	$a0 = { 5589e583ec0883c4f46a02a1c8b24000ffd0e879ffffffc9c3000000 }


condition:
	$a0
}