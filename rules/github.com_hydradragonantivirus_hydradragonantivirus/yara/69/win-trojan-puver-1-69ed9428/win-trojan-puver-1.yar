rule Win_Trojan_Puver_1
{
strings:
	$a0 = { 5d81edac058cc80500108ec0b919008d9ee40533ff0657512e8b3781c600018bc1b93e0090 }


condition:
	$a0
}