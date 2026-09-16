rule Win_Spyware_ye_105
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]66b4704581204b7d27547f6909aee6 }


condition:
	$a0
}