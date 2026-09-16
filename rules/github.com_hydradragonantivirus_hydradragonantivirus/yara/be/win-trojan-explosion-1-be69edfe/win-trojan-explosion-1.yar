rule Win_Trojan_Explosion_1
{
strings:
	$a0 = { 3eaa0000750580fc4b7403e9de01fc515650535506 }


condition:
	$a0
}