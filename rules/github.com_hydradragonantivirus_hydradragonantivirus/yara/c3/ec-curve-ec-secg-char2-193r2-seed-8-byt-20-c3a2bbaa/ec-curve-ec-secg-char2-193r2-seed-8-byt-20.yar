rule EC_curve__EC_SECG_CHAR2_193R2_SEED__8_byt_20_
{
strings:
	$a0 = { 10b7b4d696e676875615175137c8a16fd0da2211 }

condition:
	$a0
}