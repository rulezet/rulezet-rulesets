rule Win_Spyware_ye_207
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]cc12d623e78e39630db2ddcff79cd4 }


condition:
	$a0
}