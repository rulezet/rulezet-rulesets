rule Win_Trojan_Larry_1
{
strings:
	$a0 = { bf00028bcff3a4061ffabf84008b05a38702b85e02ab }


condition:
	$a0
}