rule EC_curve__EC_X9_62_CHAR2_239V2_SEED__8_byt_20_
{
strings:
	$a0 = { 2aa6982fdfa4d696e676875615175d266727277d }

condition:
	$a0
}