rule Win_Spyware_ye_5
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]02c80cd91d44772143680bfda5c2f2 }


condition:
	$a0
}