rule PKCS_DigestDecoration_Tiger__8_byt_19_
{
strings:
	$a0 = { 3029300d06092b06010401da470c0205000418 }

condition:
	$a0
}