rule Win_Trojan_MacGyver_4
{
strings:
	$a0 = { b9001033d2e81a0872213bc1751db800428b16ea0e8b0eec0ee80608b44033c9e8ff077206 }


condition:
	$a0
}