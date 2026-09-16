rule Win_Trojan_Dream_2
{
strings:
	$a0 = { e2e51fc11a2944aaf42a96f41436f3261fa9a6411a736e209a957229575d01c2e4917f2819ef37291bbfa5 }


condition:
	$a0
}