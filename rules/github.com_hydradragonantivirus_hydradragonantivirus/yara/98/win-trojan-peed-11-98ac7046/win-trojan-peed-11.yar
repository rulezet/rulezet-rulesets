rule Win_Trojan_Peed_11
{
strings:
	$a0 = { 89c381c3??????006a2481c3ff235134ff9301dcaecbb8f6 }


condition:
	$a0
}