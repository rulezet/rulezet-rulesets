rule Win_Trojan_W_121
{
strings:
	$a0 = { b953000000f5f9b9a7030000f58da800f0bffff88d9558104000f8eb2accf1 }


condition:
	$a0
}