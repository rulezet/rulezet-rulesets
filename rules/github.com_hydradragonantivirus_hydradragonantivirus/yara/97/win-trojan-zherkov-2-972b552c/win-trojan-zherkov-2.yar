rule Win_Trojan_Zherkov_2
{
strings:
	$a0 = { 1ee800005e2e8a44f93c0074118bfe83c71a90b90007 }


condition:
	$a0
}