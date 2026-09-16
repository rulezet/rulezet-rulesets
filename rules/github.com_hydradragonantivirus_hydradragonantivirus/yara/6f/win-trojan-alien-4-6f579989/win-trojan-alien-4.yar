rule Win_Trojan_Alien_4
{
strings:
	$a0 = { a7a6c2bdcfa2ebe7efe8c2f489cfa5c2cac192c1f2a6c2f498cfa5c2cac1c2f499cfa5c2cac1c2f4c1f2a6cfa5c2cac1c2bcbd }


condition:
	$a0
}