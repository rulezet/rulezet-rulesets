rule Win_Trojan_Dream_3
{
strings:
	$a0 = { 0e3e14ba0001e86bff72cb3b063e1475c5b8004233c933d2e859ffb440b90500ba2e03e84e }


condition:
	$a0
}