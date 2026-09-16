rule Win_Trojan_Peed_367
{
strings:
	$a0 = { 81efbdeeffff81ff431100000f848300000081ffd1d300007f7bb95f3451ff48 }


condition:
	$a0
}