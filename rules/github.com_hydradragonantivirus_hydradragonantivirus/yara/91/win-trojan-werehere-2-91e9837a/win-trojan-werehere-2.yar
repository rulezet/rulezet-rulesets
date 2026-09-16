rule Win_Trojan_Werehere_2
{
strings:
	$a0 = { f800cb1eb8f000508becff5e0058 }


condition:
	$a0
}