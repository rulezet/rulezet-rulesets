rule Win_Trojan_Komp_1
{
strings:
	$a0 = { 012e75f8be0701438dbf0b01b90400fcf3a4ba2901 }


condition:
	$a0
}