rule Win_Trojan_Baloo_3
{
strings:
	$a0 = { 43b000ba7603cd217303e9defe2e890e4003b90000e8adffb43cba7603b90000cd217303e9c4fe }


condition:
	$a0
}