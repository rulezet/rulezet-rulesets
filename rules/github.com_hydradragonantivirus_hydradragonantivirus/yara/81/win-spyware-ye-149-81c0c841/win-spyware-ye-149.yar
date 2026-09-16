rule Win_Spyware_ye_149
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]92589c69add4873153781b8d355202 }


condition:
	$a0
}