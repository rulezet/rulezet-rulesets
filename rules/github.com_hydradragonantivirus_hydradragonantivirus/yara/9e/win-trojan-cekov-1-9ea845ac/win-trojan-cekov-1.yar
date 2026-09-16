rule Win_Trojan_Cekov_1
{
strings:
	$a0 = { 2a07c7064c00430058a34e008ec0be000633ff59f2a4071f5e5f5ab80102bb007cb101cd13ea00 }


condition:
	$a0
}