rule Win_Trojan_Gen_147
{
strings:
	$a0 = { 4d005589e5b802029acd024d0081ec0202b02850e8e9fda15a000595008946fea15a00058b003b46fe774ca35a }


condition:
	$a0
}