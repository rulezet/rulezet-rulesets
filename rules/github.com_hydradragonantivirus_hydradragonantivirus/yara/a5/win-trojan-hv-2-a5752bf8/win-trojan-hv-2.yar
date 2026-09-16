rule Win_Trojan_HV_2
{
strings:
	$a0 = { 4ecd217303e9a3008cd88ec0e8cf00 }


condition:
	$a0
}