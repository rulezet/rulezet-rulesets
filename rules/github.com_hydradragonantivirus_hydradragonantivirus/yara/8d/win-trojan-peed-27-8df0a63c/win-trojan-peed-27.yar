rule Win_Trojan_Peed_27
{
strings:
	$a0 = { eed928dab640a3d2ab5fbc4bb002ac17 }


condition:
	$a0
}