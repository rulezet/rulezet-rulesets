rule Win_Trojan_Leprosy_58
{
strings:
	$a0 = { b42ccd2180f91e7d28e90000ba7502b44e33c9cd21720fe93800b44fcd213d12007403e92c00ba7b02b43bcd21 }


condition:
	$a0
}