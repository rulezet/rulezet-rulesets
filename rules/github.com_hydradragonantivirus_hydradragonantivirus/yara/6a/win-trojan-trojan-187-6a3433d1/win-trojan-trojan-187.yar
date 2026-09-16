rule Win_Trojan_Trojan_187
{
strings:
	$a0 = { f00ab44febf00e1f1607bf0001be5302a4a5161fba8000b41acd2158cb33c9ba0e0bb80143cd21 }


condition:
	$a0
}