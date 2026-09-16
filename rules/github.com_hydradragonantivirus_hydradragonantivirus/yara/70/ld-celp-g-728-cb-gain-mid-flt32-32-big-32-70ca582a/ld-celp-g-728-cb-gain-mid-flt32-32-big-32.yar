rule LD_CELP_G_728_cb_gain_mid__flt32___32_big_32_
{
strings:
	$a0 = { 3f3580003f9ed000400af60000000000bf358000bf9ed000c00af60000000000 }

condition:
	$a0
}