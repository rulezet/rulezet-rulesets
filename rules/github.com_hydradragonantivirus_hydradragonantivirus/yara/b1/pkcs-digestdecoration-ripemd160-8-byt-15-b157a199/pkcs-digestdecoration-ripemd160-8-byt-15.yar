rule PKCS_DigestDecoration_RIPEMD160__8_byt_15_
{
strings:
	$a0 = { 3021300906052b2403020105000414 }

condition:
	$a0
}