rule Win_Trojan_Peed_99
{
strings:
	$a0 = { e8d0000000f7da291424c35589e5ad83ee }


condition:
	$a0
}