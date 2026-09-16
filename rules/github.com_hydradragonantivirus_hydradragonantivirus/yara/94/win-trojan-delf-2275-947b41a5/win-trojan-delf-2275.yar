rule Win_Trojan_Delf_2275
{
strings:
	$a0 = { e925e4ffff00000094e78ce91e1c040000 }

	$a1 = { 0841514752c1 }


condition:
	$a0 and $a1
}