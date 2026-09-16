rule EC_curve__EC_X9_62_CHAR2_239V3_SEED__8_byt_20_
{
strings:
	$a0 = { 9e076f4d696e676875615175e11e9fdd77f92041 }

condition:
	$a0
}