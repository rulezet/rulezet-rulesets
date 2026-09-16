rule Win_Trojan_Eraser_3
{
strings:
	$a0 = { 1f12be1f01b90001f3a5b403bb1f04ba0000b901280e07b008cd13cd20 }


condition:
	$a0
}