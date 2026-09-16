rule Win_Spyware_ye_102
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]63a96dba7e25507a244974660eabdb }


condition:
	$a0
}