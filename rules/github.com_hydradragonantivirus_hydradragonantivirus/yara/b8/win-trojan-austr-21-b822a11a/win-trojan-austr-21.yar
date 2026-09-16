rule Win_Trojan_Austr_21
{
strings:
	$a0 = { 40b94f02ba0001cd21b8004233c933d2cd210e0e1f07ba }


condition:
	$a0
}