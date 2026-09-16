rule Win_Trojan_Offspring_2
{
strings:
	$a0 = { 9090bf????90b92d028135????479090479090e2f490bd }


condition:
	$a0
}