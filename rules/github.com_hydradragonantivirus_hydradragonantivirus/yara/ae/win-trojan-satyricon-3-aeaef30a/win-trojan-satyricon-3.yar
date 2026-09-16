rule Win_Trojan_Satyricon_3
{
strings:
	$a0 = { b3005589e5b800069a3005b30081ec000668a01e9a8a02b300a3b8028916ba0268a01e9a8a02b300a3bc028916 }


condition:
	$a0
}