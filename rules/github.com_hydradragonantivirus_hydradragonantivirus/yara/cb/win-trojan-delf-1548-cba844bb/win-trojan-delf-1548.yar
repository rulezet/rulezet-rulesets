rule Win_Trojan_Delf_1548
{
strings:
	$a0 = { 508d55f4b84c534000e802f4ffff8b45f4e89ee5ffff8bd0b98c534000b802000080e845ffffff33c05a5959648910683d534000 }


condition:
	$a0
}