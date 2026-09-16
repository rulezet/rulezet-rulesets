rule Win_Trojan_Supra_1
{
strings:
	$a0 = { ac01b5fecd218bf2803c3a741550b8004233c933d2cd2159b44081c1ac00fec6cd21b43ecd }


condition:
	$a0
}