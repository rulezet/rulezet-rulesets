rule Win_Trojan_Tazmanian_1
{
strings:
	$a0 = { b90000b001b443cd21b002b43dcd21a307088bd8b91400baeb07b43fcd21bbeb078a260301 }


condition:
	$a0
}