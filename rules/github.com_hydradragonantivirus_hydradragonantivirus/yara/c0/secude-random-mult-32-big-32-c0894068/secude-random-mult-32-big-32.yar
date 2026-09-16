rule SecuDE_random_mult__32_big_32_
{
strings:
	$a0 = { 1234567589abcdef471108151f2e3d4c256345fcfdbc24542345fbacfd6a87fb }

condition:
	$a0
}