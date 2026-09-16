rule Win_Trojan_Peed_88
{
strings:
	$a0 = { b870??40008?0c24[0-30]69c034120000bf34?44000 }


condition:
	$a0
}