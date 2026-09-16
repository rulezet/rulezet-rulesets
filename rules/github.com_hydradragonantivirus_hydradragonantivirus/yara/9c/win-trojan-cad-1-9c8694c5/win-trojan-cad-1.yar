rule Win_Trojan_CAD_1
{
strings:
	$a0 = { fe72e0b43fbab005b91c00e852fe }


condition:
	$a0
}