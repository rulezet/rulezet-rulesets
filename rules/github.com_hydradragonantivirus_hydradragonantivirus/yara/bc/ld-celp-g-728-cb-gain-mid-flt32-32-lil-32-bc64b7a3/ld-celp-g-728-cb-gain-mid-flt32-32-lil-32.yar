rule LD_CELP_G_728_cb_gain_mid__flt32___32_lil_32_
{
strings:
	$a0 = { 0080353f00d09e3f00f60a4000000000008035bf00d09ebf00f60ac000000000 }

condition:
	$a0
}