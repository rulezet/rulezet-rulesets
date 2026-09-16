rule Win_Trojan_KillWin_15
{
strings:
	$a0 = { 72656e616d6520633a5c77696e646f77735c2a2e2a20633a5c77696e646f77735c2a2e65727220 }


condition:
	$a0
}