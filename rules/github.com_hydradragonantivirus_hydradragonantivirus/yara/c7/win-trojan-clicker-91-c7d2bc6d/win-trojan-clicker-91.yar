rule Win_Trojan_Clicker_91
{
strings:
	$a0 = { 420049004e004100520059 }

	$a1 = { 436c6952616e646f6d[0-19]436c694e6f6e6365 }


condition:
	$a0 and $a1
}