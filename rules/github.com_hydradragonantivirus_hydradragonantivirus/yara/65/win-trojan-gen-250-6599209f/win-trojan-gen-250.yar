rule Win_Trojan_Gen_250
{
strings:
	$a0 = { 24012025073a0140085589e5b8c8019a7c02360181ec010009c47e0406578d7eba1657b8 }


condition:
	$a0
}