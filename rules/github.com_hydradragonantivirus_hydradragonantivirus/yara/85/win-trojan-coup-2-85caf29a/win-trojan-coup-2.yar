rule Win_Trojan_Coup_2
{
strings:
	$a0 = { 86008306860004832e130404b8009f500750891e8600 }


condition:
	$a0
}