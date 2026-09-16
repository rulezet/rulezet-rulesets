rule Win_Trojan_VB_1092
{
strings:
	$a0 = { 5c00520075006e005c00530069006e0061007000700073 }


condition:
	$a0
}