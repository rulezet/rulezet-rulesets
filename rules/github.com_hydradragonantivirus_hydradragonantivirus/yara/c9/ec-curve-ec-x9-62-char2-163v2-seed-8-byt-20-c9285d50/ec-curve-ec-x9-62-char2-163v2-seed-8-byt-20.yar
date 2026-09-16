rule EC_curve__EC_X9_62_CHAR2_163V2_SEED__8_byt_20_
{
strings:
	$a0 = { 53814c050d44d696e67687561517580ca4e29ffd }

condition:
	$a0
}