rule Win_Trojan_BigMouse_2
{
strings:
	$a0 = { 5b83c311b9a8010e1f813720294343e2f8 }


condition:
	$a0
}