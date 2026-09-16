rule Win_Trojan_C_6
{
strings:
	$a0 = { 08e670e471a23b01ba1902b8023dcd21 }


condition:
	$a0
}