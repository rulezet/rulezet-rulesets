rule Win_Trojan_Mosquito_4
{
strings:
	$a0 = { fd77232d030089862b02b440b965018d960001cd21b80042e84800b440b904008d962a02cd21 }


condition:
	$a0
}