rule Win_Trojan_Bebe_2
{
strings:
	$a0 = { d3eb240f3c00740143891e0c00c7 }


condition:
	$a0
}