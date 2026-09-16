rule Win_Trojan_Vgen_1
{
strings:
	$a0 = { 30cd2186c43d0a03723fb434cd21891e64018c066601b82f35cd21891e5c018c065e011e070e1fbabc00b82f25cd21 }


condition:
	$a0
}