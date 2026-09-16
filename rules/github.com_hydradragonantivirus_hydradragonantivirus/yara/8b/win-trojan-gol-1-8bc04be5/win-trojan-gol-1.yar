rule Win_Trojan_Gol_1
{
strings:
	$a0 = { cd2173e3b409ba3501cd21cd202a2e434f4d00556e64 }


condition:
	$a0
}