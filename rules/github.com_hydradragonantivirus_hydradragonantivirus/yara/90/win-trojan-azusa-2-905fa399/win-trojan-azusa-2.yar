rule Win_Trojan_Azusa_2
{
strings:
	$a0 = { b90827ba0001cd1372f10e07b80102bb }


condition:
	$a0
}