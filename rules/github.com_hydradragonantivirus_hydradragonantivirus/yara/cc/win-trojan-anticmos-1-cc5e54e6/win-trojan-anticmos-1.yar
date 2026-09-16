rule Win_Trojan_AntiCMOS_1
{
strings:
	$a0 = { 2603003d02007303e8cc00e8e800581f2eff2e070033c0 }


condition:
	$a0
}