rule Win_Trojan_Armageddon_2
{
strings:
	$a0 = { e931005ee800005eb9f5018d9c2d00b4002e8a0732c42e8807e80e007403e913004380c405e2 }


condition:
	$a0
}