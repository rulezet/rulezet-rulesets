rule EC_curve__EC_X9_62_PRIME_239V3_SEED__8_byt_20_
{
strings:
	$a0 = { 7d7374168ffe3471b60a857686a19475d3bfa2ff }

condition:
	$a0
}