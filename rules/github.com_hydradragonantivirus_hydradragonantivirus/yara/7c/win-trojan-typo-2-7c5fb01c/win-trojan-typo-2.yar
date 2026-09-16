rule Win_Trojan_Typo_2
{
strings:
	$a0 = { c2050033c9b44fcd2173ef }


condition:
	$a0
}