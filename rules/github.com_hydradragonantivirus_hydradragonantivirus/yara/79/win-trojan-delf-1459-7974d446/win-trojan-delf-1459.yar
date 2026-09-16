rule Win_Trojan_Delf_1459
{
strings:
	$a0 = { 303130004245495f5a485500534f46 }

	$a1 = { 534556494e464f00ffffffff08000000323030 }


condition:
	$a0 and $a1
}