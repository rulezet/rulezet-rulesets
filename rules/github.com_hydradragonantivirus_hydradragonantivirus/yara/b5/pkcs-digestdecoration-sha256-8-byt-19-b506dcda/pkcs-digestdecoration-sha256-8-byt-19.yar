rule PKCS_DigestDecoration_SHA256__8_byt_19_
{
strings:
	$a0 = { 3031300d060960864801650304020105000420 }

condition:
	$a0
}