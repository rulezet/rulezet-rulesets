rule Win_Trojan_Sandy_1
{
strings:
	$a0 = { 06e86fd21c057e3cd00900783e1c6575720100548168439abbd0d201056e117468039a1386431a14 }


condition:
	$a0
}