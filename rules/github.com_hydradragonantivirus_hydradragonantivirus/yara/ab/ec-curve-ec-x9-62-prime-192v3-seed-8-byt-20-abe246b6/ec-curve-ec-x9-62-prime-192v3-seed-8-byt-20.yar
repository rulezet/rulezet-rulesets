rule EC_curve__EC_X9_62_PRIME_192V3_SEED__8_byt_20_
{
strings:
	$a0 = { c469684435deb378c4b65ca9591e2a5763059a2e }

condition:
	$a0
}