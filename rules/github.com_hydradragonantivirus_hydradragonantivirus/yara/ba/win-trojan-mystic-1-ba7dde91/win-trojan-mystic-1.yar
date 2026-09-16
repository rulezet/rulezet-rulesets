rule Win_Trojan_Mystic_1
{
strings:
	$a0 = { e800005d81ed06018d9e1201e85d01 }


condition:
	$a0
}