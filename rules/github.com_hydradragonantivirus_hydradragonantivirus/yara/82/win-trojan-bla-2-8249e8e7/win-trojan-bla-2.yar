rule Win_Trojan_Bla_2
{
strings:
	$a0 = { f03d00f07503e933008bd5b97102b440cd21b8004233c933d2cd2181c77102c60503c6450101 }


condition:
	$a0
}