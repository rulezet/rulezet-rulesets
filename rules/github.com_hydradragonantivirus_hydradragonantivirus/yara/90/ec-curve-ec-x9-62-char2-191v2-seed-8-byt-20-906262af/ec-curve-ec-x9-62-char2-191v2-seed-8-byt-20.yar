rule EC_curve__EC_X9_62_CHAR2_191V2_SEED__8_byt_20_
{
strings:
	$a0 = { 0871ef2fef24d696e6768756151758bee0d95c15 }

condition:
	$a0
}