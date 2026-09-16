rule Win_Trojan_Mummy_3
{
strings:
	$a0 = { 4800b842422e8a2432e02e882446e2f5 }


condition:
	$a0
}