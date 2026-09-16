rule Win_Trojan_DVA_4
{
strings:
	$a0 = { 8bf281ee0301c35eeb2d90b42fcd218c84ac03899cae0333d28bd681c2800281c200100e1fb41acd218994aa03c3 }


condition:
	$a0
}