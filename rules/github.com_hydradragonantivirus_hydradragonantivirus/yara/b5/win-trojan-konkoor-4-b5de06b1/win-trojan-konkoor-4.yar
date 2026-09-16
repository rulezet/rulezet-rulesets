rule Win_Trojan_Konkoor_4
{
strings:
	$a0 = { 0e9000e8a80181f966067503e98000b44a2e8b1e82002e }


condition:
	$a0
}