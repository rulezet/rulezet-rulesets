rule Win_Trojan_Byworm_1
{
strings:
	$a0 = { e800005d81ed????8b86????b948028db6????2e01042e31044646e2f6 }


condition:
	$a0
}