rule Win_Trojan_Kaszana_1
{
strings:
	$a0 = { 4242c0874942fe4140eceaedeb1fccd52342f55b8c6047f965748c60c81d19cd051b46cc151df564 }


condition:
	$a0
}