rule Win_Trojan_Cybercide_2
{
strings:
	$a0 = { 0300a3b409b4408b0e9409ba0001cd21b8004233c933d2cd21b440b90300bab309cd211f5ead24 }


condition:
	$a0
}