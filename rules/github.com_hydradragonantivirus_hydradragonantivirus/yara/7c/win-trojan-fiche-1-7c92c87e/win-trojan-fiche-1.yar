rule Win_Trojan_Fiche_1
{
strings:
	$a0 = { b42001ffb41e018bc2061fcb1e070e }


condition:
	$a0
}