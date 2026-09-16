rule Win_Trojan_Loz_1
{
strings:
	$a0 = { e800005e2e8a44e73c0074118bfe83c71a90b9dc06 }


condition:
	$a0
}