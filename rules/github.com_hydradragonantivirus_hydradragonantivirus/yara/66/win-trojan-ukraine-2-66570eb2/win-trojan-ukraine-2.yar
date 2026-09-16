rule Win_Trojan_Ukraine_2
{
strings:
	$a0 = { a9738946967a1b6ab3096d3d5c651f8fa23cfc5eb011b2c03038ebb2f6c137e7fcb6d1e5e3d2b2f8613704 }


condition:
	$a0
}