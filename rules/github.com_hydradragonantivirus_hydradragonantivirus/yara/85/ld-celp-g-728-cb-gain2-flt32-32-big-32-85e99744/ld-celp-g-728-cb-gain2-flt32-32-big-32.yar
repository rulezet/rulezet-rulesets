rule LD_CELP_G_728_cb_gain2__flt32___32_big_32_
{
strings:
	$a0 = { 3f8400003fe70000404a200040b0dc00bf840000bfe70000c04a2000c0b0dc00 }

condition:
	$a0
}