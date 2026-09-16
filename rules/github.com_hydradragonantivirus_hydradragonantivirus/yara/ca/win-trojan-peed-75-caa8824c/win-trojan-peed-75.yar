rule Win_Trojan_Peed_75
{
strings:
	$a0 = { b870b240008d0c248b4c21008d54200051ff1269c0 }


condition:
	$a0
}