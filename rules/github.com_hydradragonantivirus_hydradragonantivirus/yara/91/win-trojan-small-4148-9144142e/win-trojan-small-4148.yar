rule Win_Trojan_Small_4148
{
strings:
	$a0 = { 60bb22aaba9be80a000000bb??00000023cbc1e1035b83c30a8d5bb38b4b34 }


condition:
	$a0
}