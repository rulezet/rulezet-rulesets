rule Win_Trojan_LockJaw_1
{
strings:
	$a0 = { 5053523d004b7503e80e005a5b581f079d2eff2e }


condition:
	$a0
}