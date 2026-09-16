rule Win_Trojan_AT_II_1
{
strings:
	$a0 = { 0e0eafb027b3148ec060a761b170f3a48ed974085087 }


condition:
	$a0
}