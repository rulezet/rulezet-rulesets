rule Win_Trojan_BigMouse_3
{
strings:
	$a0 = { e800005bb9a8010e1f83c311813793194343e2f8 }


condition:
	$a0
}