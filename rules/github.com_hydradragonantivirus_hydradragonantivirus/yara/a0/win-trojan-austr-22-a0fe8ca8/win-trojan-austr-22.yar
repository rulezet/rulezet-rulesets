rule Win_Trojan_Austr_22
{
strings:
	$a0 = { cd2172618bd80e0e071fb43fb90400ba7201cd2189 }


condition:
	$a0
}