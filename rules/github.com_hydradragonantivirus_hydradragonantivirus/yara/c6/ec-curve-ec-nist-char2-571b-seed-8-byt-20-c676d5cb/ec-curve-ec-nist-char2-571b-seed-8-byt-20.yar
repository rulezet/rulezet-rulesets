rule EC_curve__EC_NIST_CHAR2_571B_SEED__8_byt_20_
{
strings:
	$a0 = { 2aa058f73a0e33ab486b0f610410c53a7f132310 }

condition:
	$a0
}