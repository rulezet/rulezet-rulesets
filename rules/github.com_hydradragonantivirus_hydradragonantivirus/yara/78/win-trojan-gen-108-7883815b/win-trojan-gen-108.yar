rule Win_Trojan_Gen_108
{
strings:
	$a0 = { 023dba1f0003d6cd217303e99900 }


condition:
	$a0
}