rule Win_Trojan_Peed_125
{
strings:
	$a0 = { b887d61200e9b100000089e00110c3bf00??a8e1bbf9ffffff01c789f89683c3 }


condition:
	$a0
}