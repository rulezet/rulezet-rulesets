rule Win_Trojan_Zbot_1237
{
strings:
	$a0 = { 3489230112ef2323cd78de899a45cd12[0-16]303534007169777238776a69646b6c }


condition:
	$a0
}