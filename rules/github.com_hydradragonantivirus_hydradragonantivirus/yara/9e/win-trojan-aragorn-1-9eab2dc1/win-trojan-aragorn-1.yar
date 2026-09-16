rule Win_Trojan_Aragorn_1
{
strings:
	$a0 = { 0133c08a265f018826160233c0803e130201742cb43d }


condition:
	$a0
}