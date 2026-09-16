rule Win_Trojan_Stinkfoot_3
{
strings:
	$a0 = { 2f00be000080b44201d246e2f8c3be }


condition:
	$a0
}