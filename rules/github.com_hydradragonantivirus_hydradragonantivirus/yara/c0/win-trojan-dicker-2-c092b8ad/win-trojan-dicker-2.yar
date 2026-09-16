rule Win_Trojan_Dicker_2
{
strings:
	$a0 = { 7503bb99003d004b74052eff2e34019c5053515206 }


condition:
	$a0
}