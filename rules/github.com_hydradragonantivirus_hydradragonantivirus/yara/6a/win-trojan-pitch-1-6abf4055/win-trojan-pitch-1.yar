rule Win_Trojan_Pitch_1
{
strings:
	$a0 = { 1acd211fe85c00e81401b088cd473c44743fb448bb2a00b104d3eb43cd215007bec102bf0200b9 }


condition:
	$a0
}