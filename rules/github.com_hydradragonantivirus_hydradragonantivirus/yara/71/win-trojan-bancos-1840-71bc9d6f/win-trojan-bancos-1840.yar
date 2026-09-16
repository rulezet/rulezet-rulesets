rule Win_Trojan_Bancos_1840
{
strings:
	$a0 = { 8a94877feeb26b57dc057f4fae2f953de636e1dbfe0a5e6ccc6d35b99e40483545fa3a3122b040872b9569b577ae0d1a7ecc367f59190a4ace11749c3aba898075a07a94bbe0 }


condition:
	$a0
}