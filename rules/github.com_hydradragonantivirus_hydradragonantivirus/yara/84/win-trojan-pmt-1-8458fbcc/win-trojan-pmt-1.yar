rule Win_Trojan_PMT_1
{
strings:
	$a0 = { be0d0157b99100f3a4c3be9101fbf48ed189ccbf0001588b0e010181e99101f3a4be0001e4 }


condition:
	$a0
}