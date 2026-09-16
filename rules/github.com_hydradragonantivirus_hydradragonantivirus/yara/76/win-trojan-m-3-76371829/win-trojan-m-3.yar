rule Win_Trojan_M_3
{
strings:
	$a0 = { b435b021cd212e891e6d052e8c066f05 }


condition:
	$a0
}