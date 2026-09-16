rule Win_Trojan_Gen_230
{
strings:
	$a0 = { 39ca85fb83c4065883e71f81ff1fc7960080fc397303bfffff57b454feffb88bec804e160158 }


condition:
	$a0
}