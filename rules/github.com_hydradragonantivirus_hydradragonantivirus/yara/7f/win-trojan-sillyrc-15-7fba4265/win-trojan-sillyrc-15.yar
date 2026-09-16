rule Win_Trojan_SillyRC_15
{
strings:
	$a0 = { 83ee035633c08ec026813e080333c0740ebf0003b9e000fcf3a49a420300005e1e0781c63800bf0001b90500fcf3a4 }


condition:
	$a0
}