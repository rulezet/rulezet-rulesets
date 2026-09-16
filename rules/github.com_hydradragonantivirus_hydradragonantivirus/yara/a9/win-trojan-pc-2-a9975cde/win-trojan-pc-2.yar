rule Win_Trojan_PC_2
{
strings:
	$a0 = { 02cd13eb0190be990a81ee030103f38b }


condition:
	$a0
}