rule Win_Trojan_Deicide_10
{
strings:
	$a0 = { 9c505351521e06165657b42acd2180fe0b721880 }


condition:
	$a0
}