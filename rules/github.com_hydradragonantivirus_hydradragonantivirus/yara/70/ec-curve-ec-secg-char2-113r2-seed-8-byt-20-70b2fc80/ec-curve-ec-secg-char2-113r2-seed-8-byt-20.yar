rule EC_curve__EC_SECG_CHAR2_113R2_SEED__8_byt_20_
{
strings:
	$a0 = { 10c0fb15760860def1eef4d696e676875615175d }

condition:
	$a0
}