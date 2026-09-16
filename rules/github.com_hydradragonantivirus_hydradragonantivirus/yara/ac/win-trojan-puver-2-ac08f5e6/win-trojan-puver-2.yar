rule Win_Trojan_Puver_2
{
strings:
	$a0 = { 5d81ed82058cc80500108ec0b919008d9eb80533ff0657512e8b3781c600018bc1b93c0048 }


condition:
	$a0
}