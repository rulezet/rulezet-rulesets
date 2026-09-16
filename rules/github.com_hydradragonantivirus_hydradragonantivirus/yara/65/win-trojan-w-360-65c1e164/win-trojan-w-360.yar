rule Win_Trojan_W_360
{
strings:
	$a0 = { 51b90400000083f9040f8518feffff90909059c3e8e5feffff3c010f841fffffff3c020f8457 }


condition:
	$a0
}