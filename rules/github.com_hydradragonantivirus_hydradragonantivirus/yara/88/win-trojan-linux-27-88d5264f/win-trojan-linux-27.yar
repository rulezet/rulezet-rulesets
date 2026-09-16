rule Win_Trojan_Linux_27
{
strings:
	$a0 = { ec0883ec086a016a00e8c2fcffff83c41083ec086a0f6a00e8b3fcffff83c410c9c389f65589e557565381ec5c88010083ec046a066a016a02e8b2fcffff83c4 }


condition:
	$a0
}