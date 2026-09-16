rule Win_Trojan_2_1
{
strings:
	$a0 = { b80102bbb404b90100ba80000e07cd13 }


condition:
	$a0
}