rule Win_Trojan_CAZ_2
{
strings:
	$a0 = { b80102bb8704b90100ba80000e07cd13 }


condition:
	$a0
}