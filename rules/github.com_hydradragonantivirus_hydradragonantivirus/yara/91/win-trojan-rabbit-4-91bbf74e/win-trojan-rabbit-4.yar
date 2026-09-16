rule Win_Trojan_Rabbit_4
{
strings:
	$a0 = { 5d81ed03018db62002bf0001a5a58d962402b41acd21b44e33c9fe8ee2018d96e201cd21fe }


condition:
	$a0
}