rule PSX_VAG_f_decoder__flt32___32_lil_40_
{
strings:
	$a0 = { 00000000000000000000703f000000000000e63f000050bf0000c43f00005cbf0000f43f000070bf }

condition:
	$a0
}