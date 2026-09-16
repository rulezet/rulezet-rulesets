rule Win_Trojan_Sarov_2
{
strings:
	$a0 = { e80100465e81ee980456ba950480341e464a75f9 }


condition:
	$a0
}