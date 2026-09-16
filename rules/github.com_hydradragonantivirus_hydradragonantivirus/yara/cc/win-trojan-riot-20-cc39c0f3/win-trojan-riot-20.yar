rule Win_Trojan_Riot_20
{
strings:
	$a0 = { faba4559cd16e800005d81ed0c00e81400eb24e80f00b440b958028bd5cd21e80300c3 }


condition:
	$a0
}