rule Win_Trojan_Sistor_10
{
strings:
	$a0 = { 078bd889c1053936cd213bc1744d83fcf072488cc848 }


condition:
	$a0
}