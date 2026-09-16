rule PSX_VAG_f_decoder__flt32___32_big_40_
{
strings:
	$a0 = { 00000000000000003f700000000000003fe60000bf5000003fc40000bf5c00003ff40000bf700000 }

condition:
	$a0
}