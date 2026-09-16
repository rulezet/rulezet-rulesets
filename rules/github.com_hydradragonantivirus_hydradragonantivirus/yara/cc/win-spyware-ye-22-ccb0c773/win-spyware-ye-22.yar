rule Win_Spyware_ye_22
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]13d91dea2e5500aad4f9a416bedb8b }


condition:
	$a0
}