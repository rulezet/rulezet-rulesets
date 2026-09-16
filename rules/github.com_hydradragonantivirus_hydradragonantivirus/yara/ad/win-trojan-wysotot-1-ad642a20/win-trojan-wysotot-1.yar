rule Win_Trojan_Wysotot_1
{
strings:
	$a0 = { 453a5c736f66743336355c6558515c62696e5c52656c656173655c6558422e706462 }


condition:
	$a0
}