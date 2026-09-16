rule Win_Trojan_PlastiqueII_2
{
strings:
	$a0 = { 06d3e08ed833f68b443e3dcb3c7434 }


condition:
	$a0
}