rule Win_Trojan_Austr_31
{
strings:
	$a0 = { 2201ba0001cd21b8004233c933d2cd21b440b90400 }


condition:
	$a0
}