rule Win_Trojan_Kamikaze_1
{
strings:
	$a0 = { baeb008eda8c063e0033ed8bc4051300 }


condition:
	$a0
}