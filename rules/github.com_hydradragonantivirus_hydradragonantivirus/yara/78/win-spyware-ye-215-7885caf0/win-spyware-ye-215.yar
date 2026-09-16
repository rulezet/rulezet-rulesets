rule Win_Spyware_ye_215
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d41ade2bef96c1eb953a65577f245c }


condition:
	$a0
}