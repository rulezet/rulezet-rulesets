rule Win_Trojan_Delf_1583
{
strings:
	$a0 = { 616e646100002e2e0000ffffffff09000000776f6f6f6c2e646174000000558bec6a006a00535657 }


condition:
	$a0
}