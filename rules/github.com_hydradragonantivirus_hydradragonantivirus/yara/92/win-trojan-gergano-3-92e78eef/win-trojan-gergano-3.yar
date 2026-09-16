rule Win_Trojan_Gergano_3
{
strings:
	$a0 = { b93000f3a4e97efd5e81c60001bf0001b9c201f3a4 }


condition:
	$a0
}