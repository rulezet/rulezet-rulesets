rule Win_Spyware_ye_177
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ae7cb80dc9e893c5ef9cc73151762e }


condition:
	$a0
}