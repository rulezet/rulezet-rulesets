rule Win_Trojan_B_74
{
strings:
	$a0 = { 3300f3a4b8010333dbb90100cd13075b5f5e595b589dca020080fc4b7405ea }


condition:
	$a0
}