rule Win_Trojan__1585_0001_001_1
{
strings:
	$a0 = { 21b4402e8b0ec3011e2e8e1ecb01ba0000cd211fb801572e8b0ec5012e8b16c701cd217225b43e }


condition:
	$a0
}