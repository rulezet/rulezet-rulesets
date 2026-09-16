rule Win_Trojan_H_2
{
strings:
	$a0 = { 0102bf3412cd1381ff21437503e92601 }


condition:
	$a0
}