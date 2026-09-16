rule Win_Trojan_SolarWind_1
{
strings:
	$a0 = { 33c050068cc88ed88bd8b820008ec026803e00001e743d33ff33f6b90001f3a533c08ed8a14c0026a3a301a14e0026 }


condition:
	$a0
}