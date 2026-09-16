rule Win_Spyware_ye_255
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]fcc206d317bee9933d620dffa7cc84 }


condition:
	$a0
}