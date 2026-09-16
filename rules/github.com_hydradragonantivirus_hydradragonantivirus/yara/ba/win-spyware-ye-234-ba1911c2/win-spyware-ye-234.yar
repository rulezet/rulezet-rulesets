rule Win_Spyware_ye_234
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e735f1c602a1d4862855786202a7df }


condition:
	$a0
}