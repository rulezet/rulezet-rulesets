rule Win_Trojan_Bored_1
{
strings:
	$a0 = { 1fb008e670e4713c027521b90100bb8b0033d2be257cb40242cd10b409ac349fcd103c0275f0f4 }


condition:
	$a0
}