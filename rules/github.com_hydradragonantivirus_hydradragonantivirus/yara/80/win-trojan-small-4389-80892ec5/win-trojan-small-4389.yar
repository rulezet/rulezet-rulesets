rule Win_Trojan_Small_4389
{
strings:
	$a0 = { e8??000000e8??000000e8[0-255]5681ee64f6ffff5656585f5ec3 }


condition:
	$a0
}