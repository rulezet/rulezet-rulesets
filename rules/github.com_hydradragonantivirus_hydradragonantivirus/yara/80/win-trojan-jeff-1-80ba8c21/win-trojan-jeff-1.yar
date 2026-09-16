rule Win_Trojan_Jeff_1
{
strings:
	$a0 = { ff8ec0b93f0033d232e48bd9268a }


condition:
	$a0
}