rule Win_Trojan_Kid_2
{
strings:
	$a0 = { cd210653e800005a81c2a901b41acd218bf283c61e8bde83eb242e8b072ea300012e8b47022ea302012e8b47042e }


condition:
	$a0
}