rule Win_Trojan_Bancos_713
{
strings:
	$a0 = { 7aef3e3d298df6df319488927e093c17f4e266a58dcaba585eb5c6de88998ef4febffac4db3bc564d4a480d73001207664566ad39f392db57cba736923fa726f29 }


condition:
	$a0
}