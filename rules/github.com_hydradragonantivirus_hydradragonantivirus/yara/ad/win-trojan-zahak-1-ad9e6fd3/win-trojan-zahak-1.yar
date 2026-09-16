rule Win_Trojan_Zahak_1
{
strings:
	$a0 = { 0901aa7503e8db00cd2d81f9aaaa7403e88402588ed8 }


condition:
	$a0
}