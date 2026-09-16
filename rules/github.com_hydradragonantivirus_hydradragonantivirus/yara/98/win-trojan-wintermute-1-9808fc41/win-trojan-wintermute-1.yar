rule Win_Trojan_Wintermute_1
{
strings:
	$a0 = { 06bc035200b80042e83800b91c00bab2030e1fb440cc595a580bf674054080c91fcc5a595840cd }


condition:
	$a0
}