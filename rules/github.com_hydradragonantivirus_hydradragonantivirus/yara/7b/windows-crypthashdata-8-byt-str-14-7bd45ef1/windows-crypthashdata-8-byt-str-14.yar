rule Windows_CryptHashData__8_byt_STR_14_
{
strings:
	$a0 = { 4372797074486173684461746100 }

condition:
	$a0
}