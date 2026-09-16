rule Win_Trojan_VGEN_190
{
strings:
	$a0 = { 04008d96dc02ffd2a8bc255531108e8d1310ae8c1314968e1362e744e744eb2034bd9d0ead9addb90e9f9d2e5899af }


condition:
	$a0
}