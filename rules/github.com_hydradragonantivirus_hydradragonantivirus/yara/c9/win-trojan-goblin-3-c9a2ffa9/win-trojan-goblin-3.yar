rule Win_Trojan_Goblin_3
{
strings:
	$a0 = { e800005eb99c048bfe83c7102e8035??47e2f9 }


condition:
	$a0
}