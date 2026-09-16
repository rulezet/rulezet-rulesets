rule Win_Trojan_Apo_1
{
strings:
	$a0 = { b90200ba2901cd21b8024233c98bd1cd21b93608b440ba0001cd21ba4801b90600b440cd21b8 }


condition:
	$a0
}