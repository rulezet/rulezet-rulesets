rule Win_Trojan_Cordobes_2
{
strings:
	$a0 = { 799f734eebefe909d806f13f878eaa25c9651300e09fe979 }


condition:
	$a0
}