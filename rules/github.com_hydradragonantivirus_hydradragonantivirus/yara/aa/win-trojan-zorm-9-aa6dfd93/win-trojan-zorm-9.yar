rule Win_Trojan_Zorm_9
{
strings:
	$a0 = { 33c98ed8be2a00b913002d0100bf10048b1dcd110501002bc393b0ff02c32e8a2432e02e882446e2f5 }


condition:
	$a0
}