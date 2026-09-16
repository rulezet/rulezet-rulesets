rule Win_Trojan_Peed_400
{
strings:
	$a0 = { e8a600000068cbdfffff56e8a800000035????????5189f96a01e84f00000059e87a000000b8d33e000031d2b909 }


condition:
	$a0
}