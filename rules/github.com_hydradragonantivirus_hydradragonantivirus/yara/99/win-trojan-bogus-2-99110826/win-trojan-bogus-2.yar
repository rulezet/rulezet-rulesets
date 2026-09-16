rule Win_Trojan_Bogus_2
{
strings:
	$a0 = { 241057f2aec647ff2e5f68002040006839214000e8da0000006a00683f21400057e8f7000000 }


condition:
	$a0
}