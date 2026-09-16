rule RNG__32_lil_AND_
{
strings:
	$a0 = { ffffff7f[0-20]1df30100 }

condition:
	$a0
}