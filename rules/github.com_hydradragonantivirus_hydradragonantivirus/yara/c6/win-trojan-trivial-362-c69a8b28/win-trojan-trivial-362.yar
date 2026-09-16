rule Win_Trojan_Trivial_362
{
strings:
	$a0 = { d8b43fb90200ba5001cd21813e5001b00074d8b80042b90000ba0000cd21b440b95000ba0001cd }


condition:
	$a0
}