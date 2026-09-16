rule Win_Trojan_Forger_2
{
strings:
	$a0 = { 0102bf6587cd1381ff78567507e9e900 }


condition:
	$a0
}