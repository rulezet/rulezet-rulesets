rule Win_Spyware_ye_95
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5ca266b3771e49731d426d5f07ace4 }


condition:
	$a0
}