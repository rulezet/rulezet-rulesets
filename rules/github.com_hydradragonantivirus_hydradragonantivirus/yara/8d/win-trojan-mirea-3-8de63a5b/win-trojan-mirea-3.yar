rule Win_Trojan_Mirea_3
{
strings:
	$a0 = { c487d2fb960783c4fb910783cafb8c0783ddfc8f6f8f87fc }


condition:
	$a0
}