rule Win_Trojan_Gen_21
{
strings:
	$a0 = { 5bb440b93f04ba4605cd01b8004233c933d2cd01b440ba4305b90300cc5a59b80157cd01b43e }


condition:
	$a0
}