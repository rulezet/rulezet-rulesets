rule Win_Trojan_CrackerBack_1
{
strings:
	$a0 = { e3d0e9a4f97230a1db967e128823c3ab515c6dfad3d5b5f68d300d262cf2f07f }


condition:
	$a0
}