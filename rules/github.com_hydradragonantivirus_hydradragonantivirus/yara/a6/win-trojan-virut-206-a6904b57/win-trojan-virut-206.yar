rule Win_Trojan_Virut_206
{
strings:
	$a0 = { 90e81b0000005dc30f31c353b9990c00008bda66311003d38d4002e2f65b }


condition:
	$a0
}