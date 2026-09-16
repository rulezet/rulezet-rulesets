rule Win_Trojan_Khizhn_2
{
strings:
	$a0 = { 03e9c400a39902ba9e028bd8b90300b43fcd217303e9b00033c98bd18b1e9902b80242cd21 }


condition:
	$a0
}