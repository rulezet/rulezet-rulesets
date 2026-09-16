rule EC_curve__EC_NIST_CHAR2_283B_SEED__8_byt_20_
{
strings:
	$a0 = { 77e2b07370eb0f832a6dd5b62dfc88cd06bb84be }

condition:
	$a0
}