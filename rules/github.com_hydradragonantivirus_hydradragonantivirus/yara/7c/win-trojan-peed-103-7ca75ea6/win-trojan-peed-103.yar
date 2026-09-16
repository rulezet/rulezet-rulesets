rule Win_Trojan_Peed_103
{
strings:
	$a0 = { 6affeb74bf00??a8e1bbf9ffffff01c789f89683c3 }


condition:
	$a0
}