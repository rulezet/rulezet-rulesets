rule Win_Trojan_Torm_4
{
strings:
	$a0 = { 3fb91c00bacc0003d6cd21727480bccc004d756481bc }


condition:
	$a0
}