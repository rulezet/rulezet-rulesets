rule Win_Trojan_Eek_2
{
strings:
	$a0 = { 50e89a0659b8010050ff7606e8ea1859598946fe837efeff7503e92f0133c050ff36aa00 }


condition:
	$a0
}