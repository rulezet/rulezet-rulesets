rule Win_Trojan_ZBot_4
{
strings:
	$a0 = { 80f???67e30?f1[0-14]60 }


condition:
	$a0
}