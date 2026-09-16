rule Win_Trojan_Peed_91
{
strings:
	$a0 = { b80420400050b86500000050b80000000050608bd30fafd8575803cb61 }


condition:
	$a0
}