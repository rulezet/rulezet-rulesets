rule Win_Trojan_Syskill_1
{
strings:
	$a0 = { 6826604000ff1550704000683360400050ff1554704000a366604000eb4c }


condition:
	$a0
}