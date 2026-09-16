rule Win_Trojan_W_311
{
strings:
	$a0 = { af751199b442ff166156f3a55eabb510b440ff16b43eff16c961e9 }


condition:
	$a0
}