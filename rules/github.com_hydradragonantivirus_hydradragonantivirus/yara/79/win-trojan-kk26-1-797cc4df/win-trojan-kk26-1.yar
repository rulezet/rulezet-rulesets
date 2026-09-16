rule Win_Trojan_KK26_1
{
strings:
	$a0 = { 4102d0eb8acb83e1077534c606dc049690b40cba80008a2edb0480e51fcd13b900d0e2fefe06db }


condition:
	$a0
}