rule Win_Trojan_FatherXmas_2
{
strings:
	$a0 = { 817c7960ea77e8837c79 }


condition:
	$a0
}