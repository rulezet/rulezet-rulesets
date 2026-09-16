rule Win_Trojan_VGEN_2
{
strings:
	$a0 = { 9090909090e800008bf4bf0e02a58b2e0e02444481ed13018d9e0402ff3783c302ff37b41a8d960802cd21ccb44e }


condition:
	$a0
}