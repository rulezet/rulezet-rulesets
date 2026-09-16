rule Win_Trojan_Energizer_1
{
strings:
	$a0 = { fd77292d030050b44033d2b9f401e8dcfe587218fcbff001abb026aab000e80e00b440baef01 }


condition:
	$a0
}