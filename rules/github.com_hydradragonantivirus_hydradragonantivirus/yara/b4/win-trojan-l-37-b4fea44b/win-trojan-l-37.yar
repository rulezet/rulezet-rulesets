rule Win_Trojan_L_37
{
strings:
	$a0 = { fa32260601fb88279043fa81fbe003907eebfbc3 }


condition:
	$a0
}