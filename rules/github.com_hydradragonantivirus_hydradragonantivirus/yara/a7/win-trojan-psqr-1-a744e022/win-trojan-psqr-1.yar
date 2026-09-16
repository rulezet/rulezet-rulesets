rule Win_Trojan_PSQR_1
{
strings:
	$a0 = { 35cd212e891eba002e8c06bc00b808 }


condition:
	$a0
}