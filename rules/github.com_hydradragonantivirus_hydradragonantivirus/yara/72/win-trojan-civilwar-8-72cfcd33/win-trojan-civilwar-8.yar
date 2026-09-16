rule Win_Trojan_CivilWar_8
{
strings:
	$a0 = { 2f80f90159744a51523e8b9ef001b43fb903008d96eb }


condition:
	$a0
}