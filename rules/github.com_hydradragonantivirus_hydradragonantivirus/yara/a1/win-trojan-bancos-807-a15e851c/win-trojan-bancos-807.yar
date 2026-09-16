rule Win_Trojan_Bancos_807
{
strings:
	$a0 = { 779af68e56256fb2f7db902f938c63cbcc347ba95760cd32d0e2a1ae1c0ec02161b8bb2bee5467595b11c059812aafcc3abf4b73aaec6f5fbb7faf15ffc0d50bc7f35c67598b }


condition:
	$a0
}