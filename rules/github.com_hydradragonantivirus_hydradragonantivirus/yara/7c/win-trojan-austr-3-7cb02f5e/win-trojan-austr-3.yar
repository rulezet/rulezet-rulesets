rule Win_Trojan_Austr_3
{
strings:
	$a0 = { 9b04ba0001cd21b8004233c933d2cd21c6064a025a }


condition:
	$a0
}