rule Win_Trojan_Androm_2
{
strings:
	$a0 = { 81d15d3a0000558bec83ec0cc745f803eff20dc745fc00eff20d130590d140008b45f83572356875811d18d1400090d1 }


condition:
	$a0
}