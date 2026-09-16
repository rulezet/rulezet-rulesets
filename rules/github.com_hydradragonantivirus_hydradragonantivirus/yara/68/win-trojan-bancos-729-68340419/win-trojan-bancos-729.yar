rule Win_Trojan_Bancos_729
{
strings:
	$a0 = { fd858d21f7c55276d521d41b1fdaca6d2d9b1cb29d2ebaa79585f2ed31bef14387f0e385369b11dd8b916ab4217855c4dc1c8f4cb9ab0244cc7e1c25e6a71f845ab7d6d47101bdbf61760b3d }


condition:
	$a0
}