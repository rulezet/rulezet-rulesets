rule Win_Trojan_Aline_1
{
strings:
	$a0 = { 01b4409c2eff1e03017303eb1990ba0001b9e1032e8b1e1801b4409c2eff1e03017303eb }


condition:
	$a0
}