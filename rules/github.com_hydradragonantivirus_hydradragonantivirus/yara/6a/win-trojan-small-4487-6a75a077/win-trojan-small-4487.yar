rule Win_Trojan_Small_4487
{
strings:
	$a0 = { 8d44241c8b008d8062767504506862343504e8550000004050ba61b8fc0b5250 }


condition:
	$a0
}