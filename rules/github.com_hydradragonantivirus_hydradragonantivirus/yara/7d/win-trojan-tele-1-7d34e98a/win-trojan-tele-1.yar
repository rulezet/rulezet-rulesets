rule Win_Trojan_Tele_1
{
strings:
	$a0 = { ff01070055fd00000000ffff090300004f020000020000001203 }


condition:
	$a0
}