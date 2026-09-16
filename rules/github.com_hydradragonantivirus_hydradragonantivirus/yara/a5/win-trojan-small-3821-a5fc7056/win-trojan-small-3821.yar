rule Win_Trojan_Small_3821
{
strings:
	$a0 = { e8000000005a81c2cb0d00008d8afc04000052516a00ff15dda74000598b1424 }


condition:
	$a0
}