rule Win_Trojan_Dialer_756
{
strings:
	$a0 = { 4554564953494f4eb7ffdf7c13196164756c74692e747261666669630d7661459ac1fe6e63 }


condition:
	$a0
}