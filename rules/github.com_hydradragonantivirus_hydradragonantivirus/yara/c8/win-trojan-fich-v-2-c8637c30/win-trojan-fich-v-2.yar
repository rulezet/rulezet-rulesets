rule Win_Trojan_Fich_V_2
{
strings:
	$a0 = { 0125ba5501cd21b80325ba5501cd21bb }


condition:
	$a0
}