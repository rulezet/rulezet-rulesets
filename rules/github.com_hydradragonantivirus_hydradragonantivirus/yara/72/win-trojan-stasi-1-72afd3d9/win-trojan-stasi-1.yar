rule Win_Trojan_Stasi_1
{
strings:
	$a0 = { 2ed1062100b803002ed1062a00b807000e98072ed10639000e3f1f37cd1c }


condition:
	$a0
}