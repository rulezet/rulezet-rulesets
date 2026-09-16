rule Win_Trojan_Qwerty_1
{
strings:
	$a0 = { 57b40bcd210ac07502cd20b406b2ffcd21 }


condition:
	$a0
}