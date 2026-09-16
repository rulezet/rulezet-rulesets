rule Win_Trojan_Tabulero_1
{
strings:
	$a0 = { 022e89052e8b47042e8945022e8b47062e89450433 }


condition:
	$a0
}