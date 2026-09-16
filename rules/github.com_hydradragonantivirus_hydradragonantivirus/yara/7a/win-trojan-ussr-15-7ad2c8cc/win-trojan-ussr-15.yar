rule Win_Trojan_USSR_15
{
strings:
	$a0 = { 030150b905008bf94fbb3e0101fb031efcff8a2788a50001e2ecba0f010316fcffb41acd21ba09010316fcffb90100 }


condition:
	$a0
}