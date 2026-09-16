rule Win_Trojan_Keypress_3
{
strings:
	$a0 = { 5c03cf500633c08ec0be440326813c0707075875052e }


condition:
	$a0
}