rule Win_Trojan_Bifrose_179
{
strings:
	$a0 = { 7baafed4f5e28a5c0a0f0725d65b71b06ff19333073a26d9fd45f0d1ae87eb017ae4b9b84aa9a2cc13d8009d092bda0b56dde8ea8000ec60274c5bb0f0210012ca88f4f8 }


condition:
	$a0
}