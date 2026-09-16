rule Win_Trojan_Delf_1963
{
strings:
	$a0 = { 5033c9baa4631413a1c0701413e807f9ffff8b55e4b8c0861413e8a6ceffff8d45e0 }


condition:
	$a0
}