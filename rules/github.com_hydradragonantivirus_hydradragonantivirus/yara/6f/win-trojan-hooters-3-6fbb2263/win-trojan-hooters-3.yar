rule Win_Trojan_Hooters_3
{
strings:
	$a0 = { 2e8134252e46464f75f6cd2e2576083d24a5cd3023203a2022a39bc224a393da248b818b818be3a8a52d249a3fa3b37b26e3 }


condition:
	$a0
}