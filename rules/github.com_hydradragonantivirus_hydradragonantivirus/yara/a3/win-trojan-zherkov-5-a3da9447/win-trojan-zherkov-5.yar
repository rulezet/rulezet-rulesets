rule Win_Trojan_Zherkov_5
{
strings:
	$a0 = { e800005e2e8a44f53c0074118bfe83c71a90b9ee0a }


condition:
	$a0
}