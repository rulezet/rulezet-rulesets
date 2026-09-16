rule Win_Trojan_Kuku_4
{
strings:
	$a0 = { ffff33c08ed0b800b88ec033ed83c5038b7e0081e7fe0f }


condition:
	$a0
}