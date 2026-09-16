rule Win_Trojan_Trojan_84
{
strings:
	$a0 = { 1700bb17000e1fb4decd21b42acd2181fa0104742281f9bc077506e8c504 }


condition:
	$a0
}