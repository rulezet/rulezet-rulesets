rule Win_Trojan_Small_5372
{
strings:
	$a0 = { e8??000000e8??000000[0-255]f7d381c0ff89fffff7d08d }


condition:
	$a0
}