rule Win_Trojan_Zun_1
{
strings:
	$a0 = { 8b16240083c20f83d10083e2f0b800428b1e2200e89a00b94503ba0000b440e88f00725f }


condition:
	$a0
}