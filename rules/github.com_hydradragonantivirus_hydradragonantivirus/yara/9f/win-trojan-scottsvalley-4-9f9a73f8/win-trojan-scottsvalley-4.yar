rule Win_Trojan_ScottsValley_4
{
strings:
	$a0 = { e800005e8bde909081c63200b912082e }


condition:
	$a0
}