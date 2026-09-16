rule Win_Trojan_ARCV_27
{
strings:
	$a0 = { 5e81ee06008d841f00508dbc1f00b94c042e802d2147e2f9c3 }


condition:
	$a0
}