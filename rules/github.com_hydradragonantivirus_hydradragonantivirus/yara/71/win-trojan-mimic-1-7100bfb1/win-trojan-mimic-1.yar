rule Win_Trojan_Mimic_1
{
strings:
	$a0 = { be1501b97d09813587594747e2f8c3 }


condition:
	$a0
}