rule Win_Trojan_Peed_341
{
strings:
	$a0 = { 2d10abbe004ee869000000ab5052516a0058a1178b400089c129c087d1505050 }


condition:
	$a0
}