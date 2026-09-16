rule Win_Spyware_ye_220
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d927e330f493c6f0923f62547c1949 }


condition:
	$a0
}