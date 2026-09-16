rule Win_Trojan_Moctezuma_1
{
strings:
	$a0 = { 740851790b8b333298de062e8f0602011e2e8f0600018cc88ed8 }


condition:
	$a0
}