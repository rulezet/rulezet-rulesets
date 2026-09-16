rule LD_CELP_G_728_cb_gain_sq__flt64___64_big_64_
{
strings:
	$a0 = { 3fd103ffff5433893fea0e1fffe973904003f2d0802d0366401e8bcf43dbb32b3fd103ffff5433893fea0e1fffe973904003f2d0802d0366401e8bcf43dbb32b }

condition:
	$a0
}