rule way__32_lil_AND_
{
strings:
	$a0 = { 0b0b0000[0-20]b1b10000[0-20]aaaaaaaa[0-20]55555555[0-20]cccccccc[0-20]33333333[0-20]f0f0f0f0[0-20]0f0f0f0f[0-20]11100100 }

condition:
	$a0
}