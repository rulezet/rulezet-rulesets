rule Win_Trojan_MPTI_2
{
strings:
	$a0 = { e800005e50561e0e1ffaeb00c6440c8b8b847705fb1f83c62de8ce055e83c62f2e803c007402eb235646bf0001a5a55e }


condition:
	$a0
}