rule Win_Trojan_Austr_27
{
strings:
	$a0 = { b9bb01ba0001cd21b8004233c933d2cd21b440b90400 }


condition:
	$a0
}