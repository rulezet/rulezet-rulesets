rule Win_Trojan_Oropax_1
{
strings:
	$a0 = { e033cd213cff74238cce8ec68b36 }


condition:
	$a0
}