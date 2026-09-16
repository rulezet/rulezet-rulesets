rule Win_Trojan_DeadBoot_1
{
strings:
	$a0 = { e8000032e4cd155e1ac08d7c122c3a2e300547e2f8 }


condition:
	$a0
}