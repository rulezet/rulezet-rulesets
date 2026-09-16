rule Win_Trojan_Peed_63
{
strings:
	$a0 = { ba6540420087ca6a006a006a006a006a006a }


condition:
	$a0
}