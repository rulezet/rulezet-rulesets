rule Win_Trojan_P1_1
{
strings:
	$a0 = { 95bf000147033d8bf733c9ba7a025233 }


condition:
	$a0
}