rule Win_Spyware_ye_90
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]57a561b6721144761845685272174f }


condition:
	$a0
}