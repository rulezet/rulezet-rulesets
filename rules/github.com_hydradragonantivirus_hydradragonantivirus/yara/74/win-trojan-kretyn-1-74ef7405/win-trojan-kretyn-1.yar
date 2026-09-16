rule Win_Trojan_Kretyn_1
{
strings:
	$a0 = { 74756c756a6520696e66656b636a6920219a00006f005589e5b802029acd026f0081ec0202 }


condition:
	$a0
}