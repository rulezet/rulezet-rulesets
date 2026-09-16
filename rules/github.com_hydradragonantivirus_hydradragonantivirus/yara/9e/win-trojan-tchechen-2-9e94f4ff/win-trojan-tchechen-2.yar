rule Win_Trojan_Tchechen_2
{
strings:
	$a0 = { fa33c08ed0bc007c8bf48ec08ed8fbbf0006b90001f2a5ea1d060000bebe078b148b4c02b80102bb007ccd13505152 }


condition:
	$a0
}