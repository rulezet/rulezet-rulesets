rule Win_Trojan_PSKO_1
{
strings:
	$a0 = { bcb0054d5a7418b80fffcd213d010174d1fa8be681c4b306fb3b26060073c3b80fffcd213d0101 }


condition:
	$a0
}