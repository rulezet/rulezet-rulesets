rule Win_Trojan_Hupigon_683
{
strings:
	$a0 = { 3bc60ffac2da405bfaacac1037c16cfe6f99ba701051893b814f7f41f1571c256bc64cca057f0331d73f3730b43791e98de4e63211c25689aeefa0b0 }


condition:
	$a0
}