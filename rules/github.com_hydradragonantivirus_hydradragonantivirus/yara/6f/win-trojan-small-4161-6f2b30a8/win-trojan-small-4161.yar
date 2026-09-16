rule Win_Trojan_Small_4161
{
strings:
	$a0 = { e803000000c220008d1d17????0381eb }


condition:
	$a0
}