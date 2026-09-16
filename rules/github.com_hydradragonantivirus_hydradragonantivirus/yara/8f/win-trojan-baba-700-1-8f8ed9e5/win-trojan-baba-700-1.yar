rule Win_Trojan_Baba_700_1
{
strings:
	$a0 = { d8b44033d2b9bc02cd2133c933d2b80042cd21b440baa7 }


condition:
	$a0
}