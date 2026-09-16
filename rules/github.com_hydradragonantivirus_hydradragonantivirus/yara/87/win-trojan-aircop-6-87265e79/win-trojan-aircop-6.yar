rule Win_Trojan_Aircop_6
{
strings:
	$a0 = { 32e4cd16cd1233c0cd130e07bb0002b9 }


condition:
	$a0
}