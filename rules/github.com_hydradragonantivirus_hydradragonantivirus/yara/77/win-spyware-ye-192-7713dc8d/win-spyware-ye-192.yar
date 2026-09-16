rule Win_Spyware_ye_192
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]bd03c71cd8ffaadc862b56406005bd }


condition:
	$a0
}