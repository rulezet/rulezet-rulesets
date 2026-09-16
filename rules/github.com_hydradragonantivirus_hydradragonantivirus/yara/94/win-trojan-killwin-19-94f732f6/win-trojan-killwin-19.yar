rule Win_Trojan_KillWin_19
{
strings:
	$a0 = { 657261736520633a5c77696e646f77735c71 }


condition:
	$a0
}