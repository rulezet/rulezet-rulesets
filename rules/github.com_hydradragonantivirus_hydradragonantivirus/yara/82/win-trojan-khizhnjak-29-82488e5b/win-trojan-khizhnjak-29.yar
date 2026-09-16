rule Win_Trojan_Khizhnjak_29
{
strings:
	$a0 = { d002b000b442cd2172118d16d202b903008b1ed002b440cd217200833ed002ff74088b1ed002 }


condition:
	$a0
}