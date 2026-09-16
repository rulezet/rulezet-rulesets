rule Win_Trojan_Vengence_10
{
strings:
	$a0 = { c9bd0000cd2f3cff750b90909083fd137603e97201b8 }


condition:
	$a0
}