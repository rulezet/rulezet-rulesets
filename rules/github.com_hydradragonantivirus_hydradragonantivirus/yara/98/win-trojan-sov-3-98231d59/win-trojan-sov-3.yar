rule Win_Trojan_Sov_3
{
strings:
	$a0 = { d401e88c017303e8c001e81900e8da01071fcb2a2e }


condition:
	$a0
}