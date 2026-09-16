rule Win_Trojan_Holera_II_1
{
strings:
	$a0 = { cd215881fb96197402f9c3f8c3e8edff7327505351 }


condition:
	$a0
}