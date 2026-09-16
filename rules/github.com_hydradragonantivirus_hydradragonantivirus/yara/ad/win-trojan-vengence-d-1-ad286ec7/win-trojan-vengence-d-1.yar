rule Win_Trojan_Vengence_D_1
{
strings:
	$a0 = { b800c9bd0000cd2f3cff750b90909083fd137603e9ac00b8 }


condition:
	$a0
}