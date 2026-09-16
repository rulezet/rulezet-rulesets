rule Win_Trojan_Atom_3
{
strings:
	$a0 = { e800005d51502e8b46fa8bf583c618b941082e30042e002446e2f7 }


condition:
	$a0
}