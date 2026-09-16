rule Win_Trojan_Ieronim_2
{
strings:
	$a0 = { 04b440cd2158722b85c0740fbe0008bf00048bc8a38201f3a4ebc6721633c933d2b80242cd21 }


condition:
	$a0
}