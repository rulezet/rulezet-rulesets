rule Win_Trojan_Sniper_1
{
strings:
	$a0 = { 4c0056bf1400a5a5832e130403a11304bb4000f7e38ec031ffbe007cb90001fcf2a55e56bf4400 }


condition:
	$a0
}