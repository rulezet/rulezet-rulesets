rule Win_Trojan_DM_6
{
strings:
	$a0 = { b86302b93701be64015080349046e2fac3 }


condition:
	$a0
}