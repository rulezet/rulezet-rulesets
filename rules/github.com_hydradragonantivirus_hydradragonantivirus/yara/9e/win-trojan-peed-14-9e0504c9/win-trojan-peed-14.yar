rule Win_Trojan_Peed_14
{
strings:
	$a0 = { 89c381eb79584300f7db685eebffff8b1c18ffd352682a335f04e833 }


condition:
	$a0
}