rule Win_Trojan_Evasor_3
{
strings:
	$a0 = { 5d81ed1301b94d018db640018bfee80300eb1a90acf6d0c0c804f6d83e32863f01f6d8c0c8 }


condition:
	$a0
}