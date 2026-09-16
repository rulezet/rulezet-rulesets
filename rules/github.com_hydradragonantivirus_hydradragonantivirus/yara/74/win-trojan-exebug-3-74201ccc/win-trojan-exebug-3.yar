rule Win_Trojan_ExeBug_3
{
strings:
	$a0 = { 0103b111cd1388168a01e8110041e8040032d2ebddb801039cff1e8d01c3 }


condition:
	$a0
}