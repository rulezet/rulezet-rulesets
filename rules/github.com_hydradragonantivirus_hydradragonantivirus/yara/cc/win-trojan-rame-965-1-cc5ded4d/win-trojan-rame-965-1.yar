rule Win_Trojan_Rame_965_1
{
strings:
	$a0 = { acbd00008ad845ace82d007516538af880e70f8ad8c0eb04 }


condition:
	$a0
}