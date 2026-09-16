rule Win_Trojan_LoveMe_1
{
strings:
	$a0 = { 803453ba022e52b8b93850b95e565189e5ffd5 }


condition:
	$a0
}