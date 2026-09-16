rule EC_curve__EC_SECG_PRIME_128R1_SEED__8_byt_20_
{
strings:
	$a0 = { 000e0d4d696e6768756151750cc03a4473d03679 }

condition:
	$a0
}