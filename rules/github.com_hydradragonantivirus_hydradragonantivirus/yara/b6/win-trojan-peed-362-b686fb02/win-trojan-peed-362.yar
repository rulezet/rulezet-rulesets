rule Win_Trojan_Peed_362
{
strings:
	$a0 = { 81efbdc0ffff81ff433f000074??81ffd09a00007f }


condition:
	$a0
}