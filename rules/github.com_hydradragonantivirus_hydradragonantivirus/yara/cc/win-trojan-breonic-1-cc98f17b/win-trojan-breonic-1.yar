rule Win_Trojan_Breonic_1
{
strings:
	$a0 = { b82e746d7066ab32c0aa5133c9b43ccd21595a52519381e2ff1f83c2648bcab440cd21b43ecd21 }


condition:
	$a0
}