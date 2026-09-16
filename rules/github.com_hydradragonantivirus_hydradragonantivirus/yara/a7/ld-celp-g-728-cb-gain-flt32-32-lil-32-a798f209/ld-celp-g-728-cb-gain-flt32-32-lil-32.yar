rule LD_CELP_G_728_cb_gain__flt32___32_lil_32_
{
strings:
	$a0 = { 0000043f0000673f0020ca3f00dc3040000004bf000067bf0020cabf00dc30c0 }

condition:
	$a0
}