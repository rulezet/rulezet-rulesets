rule anti_debug__SOFTWARE__NuMega__8_byt_STR_16_
{
strings:
	$a0 = { 534f4654574152455c4e754d65676100 }

condition:
	$a0
}