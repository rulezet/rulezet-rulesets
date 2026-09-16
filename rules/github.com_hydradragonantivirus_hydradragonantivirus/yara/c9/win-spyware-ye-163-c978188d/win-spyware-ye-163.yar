rule Win_Spyware_ye_163
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a06eaa7fbbda8d3f610eb11bbbd888 }


condition:
	$a0
}