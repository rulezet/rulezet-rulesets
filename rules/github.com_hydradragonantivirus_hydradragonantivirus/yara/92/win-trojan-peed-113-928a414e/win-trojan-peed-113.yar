rule Win_Trojan_Peed_113
{
strings:
	$a0 = { 6affe9be000000f7da291424c35589e5ad83ee014e4e4ec9 }


condition:
	$a0
}