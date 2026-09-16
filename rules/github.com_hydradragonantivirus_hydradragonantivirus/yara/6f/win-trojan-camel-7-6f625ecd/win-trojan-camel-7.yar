rule Win_Trojan_Camel_7
{
strings:
	$a0 = { cd210ae475001e06b44abbffffcd2181eb2200b8004acd21b80048bb2100cd218ec0488e }


condition:
	$a0
}