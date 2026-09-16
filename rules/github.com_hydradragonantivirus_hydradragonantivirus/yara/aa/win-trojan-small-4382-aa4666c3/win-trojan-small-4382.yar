rule Win_Trojan_Small_4382
{
strings:
	$a0 = { b800004000505be8??000000e8 }


condition:
	$a0
}