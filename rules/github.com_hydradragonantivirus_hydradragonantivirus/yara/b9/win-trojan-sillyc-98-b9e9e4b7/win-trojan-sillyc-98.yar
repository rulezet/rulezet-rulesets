rule Win_Trojan_SillyC_98
{
strings:
	$a0 = { ff73d350b4408bd5b9cf00cd21b8004233c933d2cd218bf581c6cb00c604e9582d0300894401 }


condition:
	$a0
}