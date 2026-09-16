rule Win_Trojan_Mnemonix_1
{
strings:
	$a0 = { eb0690bbabf4e2fc0f01e0eb0390cd20bf0400fa25400050594c4c5b33c08ec03bd975e2fb26a18400268b1e8600 }


condition:
	$a0
}