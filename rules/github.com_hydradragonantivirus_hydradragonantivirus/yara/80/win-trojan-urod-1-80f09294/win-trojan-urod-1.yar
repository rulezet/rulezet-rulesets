rule Win_Trojan_Urod_1
{
strings:
	$a0 = { e800005e83ee04bf000187fe2bf7f7de8a84ed02eb26902a2e657865000700bf11000000000e00ae100000cb000500 }


condition:
	$a0
}