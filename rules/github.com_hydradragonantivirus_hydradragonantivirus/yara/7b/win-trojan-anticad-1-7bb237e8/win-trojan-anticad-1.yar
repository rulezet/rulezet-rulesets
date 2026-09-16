rule Win_Trojan_AntiCad_1
{
strings:
	$a0 = { 1a0f50cb2e8816460e33c08ed8c7068400ffff }


condition:
	$a0
}