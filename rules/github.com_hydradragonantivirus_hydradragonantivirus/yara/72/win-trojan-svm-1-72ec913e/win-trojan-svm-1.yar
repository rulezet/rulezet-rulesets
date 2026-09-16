rule Win_Trojan_Svm_1
{
strings:
	$a0 = { 5e83ee0356b9810483c618bb40002e311c46e2fa5e }


condition:
	$a0
}