rule Win_Trojan_LoveBuzz_1
{
strings:
	$a0 = { fc5e81ee67015656b9b2008bfead357109abe2f95ec3 }


condition:
	$a0
}