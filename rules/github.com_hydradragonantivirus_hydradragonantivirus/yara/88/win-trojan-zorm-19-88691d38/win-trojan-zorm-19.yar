rule Win_Trojan_Zorm_19
{
strings:
	$a0 = { 33c98ed9be????b913002d0100bf????8b1dcd1105010029d893b0ff00d82e8a2432e02e882446e2f5 }


condition:
	$a0
}