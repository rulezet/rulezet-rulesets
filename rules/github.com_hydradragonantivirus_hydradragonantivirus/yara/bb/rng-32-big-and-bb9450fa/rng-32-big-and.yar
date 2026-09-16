rule RNG__32_big_AND_
{
strings:
	$a0 = { 7fffffff[0-20]0001f31d }

condition:
	$a0
}