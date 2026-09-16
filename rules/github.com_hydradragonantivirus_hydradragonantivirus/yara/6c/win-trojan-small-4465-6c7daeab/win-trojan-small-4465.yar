rule Win_Trojan_Small_4465
{
strings:
	$a0 = { ff74241c588d80????7704506862343504e8590000004050baa116fe0b525051 }


condition:
	$a0
}