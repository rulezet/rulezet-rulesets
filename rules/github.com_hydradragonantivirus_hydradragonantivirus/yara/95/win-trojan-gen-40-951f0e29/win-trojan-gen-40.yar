rule Win_Trojan_Gen_40
{
strings:
	$a0 = { 02bf3412cd1381ff21437503e92601b82135cd21891e }


condition:
	$a0
}