rule Win_Spyware_ye_44
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]29f7338044631640620fb2244c6919 }


condition:
	$a0
}