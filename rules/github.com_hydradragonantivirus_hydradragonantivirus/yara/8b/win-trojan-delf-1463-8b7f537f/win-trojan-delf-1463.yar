rule Win_Trojan_Delf_1463
{
strings:
	$a0 = { ffff8175f4697a614d6a0053e89ff9ffff3b45f472386a026a008b45f4f7d850 }

	$a1 = { 2dc876400001c3ffffffff17000000796f756d6569796f }


condition:
	$a0 and $a1
}