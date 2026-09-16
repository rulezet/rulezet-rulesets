rule Win_Trojan_Pojer_3
{
strings:
	$a0 = { e800005e9e83ee09bb240003de9e2e8a9447079eb9f0062e30179e43e2f9 }


condition:
	$a0
}