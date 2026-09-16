rule EC_curve__EC_X9_62_PRIME_256V1_SEED__8_byt_20_
{
strings:
	$a0 = { c49d360886e704936a6678e1139d26b7819f7e90 }

condition:
	$a0
}