rule Win_Trojan_L_36
{
strings:
	$a0 = { fa32260701fb88279043fa81fb9a03907eebfbc3 }


condition:
	$a0
}