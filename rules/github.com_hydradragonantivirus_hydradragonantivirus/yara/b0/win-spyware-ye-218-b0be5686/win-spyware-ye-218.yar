rule Win_Spyware_ye_218
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d725e136f291c4f698c5e8d2f297cf }


condition:
	$a0
}