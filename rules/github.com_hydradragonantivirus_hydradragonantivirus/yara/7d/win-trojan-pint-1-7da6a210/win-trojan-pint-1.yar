rule Win_Trojan_Pint_1
{
strings:
	$a0 = { f84d41750a817ff64f4d7503bd8301b801f333c9cd21b802edcd2172648bd88cc88ed8b90400 }


condition:
	$a0
}