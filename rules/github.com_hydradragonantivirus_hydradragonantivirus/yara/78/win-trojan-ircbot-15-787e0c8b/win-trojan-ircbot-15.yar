rule Win_Trojan_IRCBot_15
{
strings:
	$a0 = { 6c4f5f60e29a8527b5f095400f28fdb06da54f19aeb854858dccbc66a7e28c4d47dad74edd5482af0f75646e922b0b1fa7084228a996a44f0ec7975af5423ca3 }


condition:
	$a0
}