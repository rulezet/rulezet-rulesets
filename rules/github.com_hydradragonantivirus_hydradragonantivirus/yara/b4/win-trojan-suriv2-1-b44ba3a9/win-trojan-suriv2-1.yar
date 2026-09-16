rule Win_Trojan_Suriv2_1
{
strings:
	$a0 = { f9c407722881fa010472223c03751e }


condition:
	$a0
}