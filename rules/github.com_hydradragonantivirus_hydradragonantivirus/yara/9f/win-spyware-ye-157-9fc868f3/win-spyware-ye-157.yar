rule Win_Spyware_ye_157
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9a60a471b5dc8f395b00a315bdda8a }


condition:
	$a0
}