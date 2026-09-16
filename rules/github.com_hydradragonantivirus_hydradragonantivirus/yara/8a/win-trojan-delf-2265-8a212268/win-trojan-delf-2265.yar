rule Win_Trojan_Delf_2265
{
strings:
	$a0 = { e9a726020028feffffb81c394000e869fc }

	$a1 = { 433a5c50726f67cc616d19204669 }


condition:
	$a0 and $a1
}