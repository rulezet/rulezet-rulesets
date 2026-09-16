rule Win_Trojan_Warlock_1
{
strings:
	$a0 = { 1e068bf381c621008bfe0e1f0e0753b97b038b5f01fcad }


condition:
	$a0
}