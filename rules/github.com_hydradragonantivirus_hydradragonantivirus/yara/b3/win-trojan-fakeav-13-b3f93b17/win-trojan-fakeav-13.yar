rule Win_Trojan_Fakeav_13
{
strings:
	$a0 = { eb32896100cd028d87000c510000000014da0098 }

	$a1 = { df61686f6f6f1d }


condition:
	$a0 and $a1
}