rule Win_Trojan_Gusano_1
{
strings:
	$a0 = { 3d8d16ff01cd218bd8e8c2007403e82a00b43ecd21b4 }


condition:
	$a0
}