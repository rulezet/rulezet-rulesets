rule Win_Trojan_Small_4376
{
strings:
	$a0 = { e8??000000e8??000000[0-255]8d2d96b32700e9??000000 }


condition:
	$a0
}