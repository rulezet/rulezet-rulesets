rule Win_Trojan_Trivial_358
{
strings:
	$a0 = { 0200ba4f01cd21813e4f01b00074d8b80042b90000ba0000cd21b440b95000ba0001cd21c3 }


condition:
	$a0
}