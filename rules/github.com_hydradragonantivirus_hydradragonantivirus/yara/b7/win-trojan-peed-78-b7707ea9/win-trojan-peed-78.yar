rule Win_Trojan_Peed_78
{
strings:
	$a0 = { 29c9e853000000e986000000558d6c24008d55088b5422008d028b442000c9c2 }


condition:
	$a0
}