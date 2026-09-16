rule Win_Trojan_Fab_2
{
strings:
	$a0 = { 5053515256571e062ea3????b452cd21268b5f0426c55ffc2e8c1e????fa33c08ec0 }


condition:
	$a0
}