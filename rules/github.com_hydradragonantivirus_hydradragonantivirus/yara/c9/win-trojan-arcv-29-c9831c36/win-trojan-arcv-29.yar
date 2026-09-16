rule Win_Trojan_ARCV_29
{
strings:
	$a0 = { a6fee2febe1d00462e813484be464775f6 }


condition:
	$a0
}