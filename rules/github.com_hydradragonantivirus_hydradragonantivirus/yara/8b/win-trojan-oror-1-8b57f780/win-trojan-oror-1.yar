rule Win_Trojan_Oror_1
{
strings:
	$a0 = { 449afeff58f2005263707420546f3a203c25733e004d1c7fb2ef3f2046726f6d11000048454c4f1affb1b1ef1d00000d }


condition:
	$a0
}