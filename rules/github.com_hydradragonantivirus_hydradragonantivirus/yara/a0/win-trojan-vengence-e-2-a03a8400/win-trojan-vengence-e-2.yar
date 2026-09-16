rule Win_Trojan_Vengence_E_2
{
strings:
	$a0 = { b800c9bd0000cd2f3cff750b90909083fd137603e97701b8 }


condition:
	$a0
}