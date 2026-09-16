rule Win_Trojan_L_44
{
strings:
	$a0 = { b8004233c933d2cd01b440ba4d05b90300cc5a59b80157cd01b43eccb801435a1f59cce9dafe }


condition:
	$a0
}