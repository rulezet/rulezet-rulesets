rule Win_Trojan_Sality_1047
{
strings:
	$a0 = { 02c55f83c7018a440500300780e901 }


condition:
	$a0
}