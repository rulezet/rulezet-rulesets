rule EC_curve__EC_X9_62_PRIME_192V2_SEED__8_byt_20_
{
strings:
	$a0 = { 31a92ee2029fd10d901b113e990710f0d21ac6b6 }

condition:
	$a0
}