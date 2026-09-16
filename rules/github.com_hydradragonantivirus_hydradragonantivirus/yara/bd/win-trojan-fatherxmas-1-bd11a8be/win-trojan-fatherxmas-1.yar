rule Win_Trojan_FatherXmas_1
{
strings:
	$a0 = { 023dba1f0003d6cd217303e98500 }


condition:
	$a0
}