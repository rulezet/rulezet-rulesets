rule Win_Spyware_ye_181
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b278bc09cdf4a7d1f3983badd5f2a2 }


condition:
	$a0
}