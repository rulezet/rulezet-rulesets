rule Win_Trojan_Aircop_5
{
strings:
	$a0 = { cd1633c0cd130e07bb0002b90600 }


condition:
	$a0
}