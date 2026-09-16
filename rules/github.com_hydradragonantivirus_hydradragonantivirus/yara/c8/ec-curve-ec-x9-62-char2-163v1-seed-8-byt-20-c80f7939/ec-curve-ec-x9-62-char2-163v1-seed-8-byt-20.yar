rule EC_curve__EC_X9_62_CHAR2_163V1_SEED__8_byt_20_
{
strings:
	$a0 = { d2c0fb15760860def1eef4d696e6768756151754 }

condition:
	$a0
}