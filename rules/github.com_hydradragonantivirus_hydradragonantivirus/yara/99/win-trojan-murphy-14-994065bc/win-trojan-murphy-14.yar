rule Win_Trojan_Murphy_14
{
strings:
	$a0 = { fbfe0e7b045e2e8b8497fd2ea300012e }


condition:
	$a0
}