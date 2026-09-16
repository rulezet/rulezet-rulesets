rule Win_Trojan_Ratboy_2
{
strings:
	$a0 = { 0100c33e8b860c018db63f01b97c0031044646e2fac38a }


condition:
	$a0
}