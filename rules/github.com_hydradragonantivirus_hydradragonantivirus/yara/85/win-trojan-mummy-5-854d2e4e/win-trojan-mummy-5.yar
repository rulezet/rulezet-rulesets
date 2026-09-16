rule Win_Trojan_Mummy_5
{
strings:
	$a0 = { 0665002e8c061b002e8c0629002e8c062d002e8c063100 }


condition:
	$a0
}