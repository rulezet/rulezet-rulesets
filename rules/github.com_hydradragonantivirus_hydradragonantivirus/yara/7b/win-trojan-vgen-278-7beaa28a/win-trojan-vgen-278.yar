rule Win_Trojan_VGEN_278
{
strings:
	$a0 = { c08ed833f6ada30201ada3040133c08ec033ffb82801ab8cc8abb400f6f4cd20ea33ffa10201aba10401ab8cc88ed8 }


condition:
	$a0
}