rule Win_Trojan_Mystic_2
{
strings:
	$a0 = { e800005d81ed06018d9e1201e85f01 }


condition:
	$a0
}