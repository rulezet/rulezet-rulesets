rule EC_curve__EC_X9_62_PRIME_239V2_SEED__8_byt_20_
{
strings:
	$a0 = { e8b4011604095303ca3b8099982be09fcb9ae616 }

condition:
	$a0
}