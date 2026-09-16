rule Win_Trojan_Prudents_1
{
strings:
	$a0 = { be4f04b923005651e87e03595ee8 }


condition:
	$a0
}