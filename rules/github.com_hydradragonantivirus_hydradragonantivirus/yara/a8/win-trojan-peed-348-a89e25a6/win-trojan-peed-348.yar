rule Win_Trojan_Peed_348
{
strings:
	$a0 = { d689f847ba617ec153d685c881c2f5d89101eb1981d50492440268cf05ad00f7d185c9d6f55eb99e7e5f01d641c1c344 }


condition:
	$a0
}