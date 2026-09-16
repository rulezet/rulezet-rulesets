rule EC_curve__EC_SECG_CHAR2_193R1_SEED__8_byt_20_
{
strings:
	$a0 = { 103faec74d696e676875615175777fc5b191ef30 }

condition:
	$a0
}