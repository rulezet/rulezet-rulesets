rule Win_Trojan_ScottsValley_3
{
strings:
	$a0 = { 8bde909081c63200b912082e8034 }


condition:
	$a0
}