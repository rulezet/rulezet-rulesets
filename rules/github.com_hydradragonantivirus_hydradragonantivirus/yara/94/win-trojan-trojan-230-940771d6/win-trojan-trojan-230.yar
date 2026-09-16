rule Win_Trojan_Trojan_230
{
strings:
	$a0 = { d2cd212d0300a38200b440b90d019033d2cd21b8004233c933d2cd21b440b90500ba8100cd21b4 }


condition:
	$a0
}