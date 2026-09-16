rule Win_Trojan_Small_4311
{
strings:
	$a0 = { 60e8??0000005050e8??000000e8??0000008d2d????7426e8??000000 }


condition:
	$a0
}