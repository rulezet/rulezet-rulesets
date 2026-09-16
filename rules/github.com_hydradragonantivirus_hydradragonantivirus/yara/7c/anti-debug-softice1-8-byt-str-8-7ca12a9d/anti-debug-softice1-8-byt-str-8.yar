rule anti_debug__SOFTICE1__8_byt_STR_8_
{
strings:
	$a0 = { 534f465449434531 }

condition:
	$a0
}