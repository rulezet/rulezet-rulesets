rule Win_Trojan_Peed_364
{
strings:
	$a0 = { 81efbfecffff81ff411300000f848300000081ff }


condition:
	$a0
}