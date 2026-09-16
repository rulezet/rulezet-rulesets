rule Win_Trojan_Arcv_7
{
strings:
	$a0 = { 1547e2fac390505351522e80847e0302e86effe8deff }


condition:
	$a0
}