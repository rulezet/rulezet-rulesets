rule Win_Trojan_Small_4462
{
strings:
	$a0 = { 8d44241c8b008d80????7704506862343504e8550000004050baa1e6fc0b5250 }


condition:
	$a0
}