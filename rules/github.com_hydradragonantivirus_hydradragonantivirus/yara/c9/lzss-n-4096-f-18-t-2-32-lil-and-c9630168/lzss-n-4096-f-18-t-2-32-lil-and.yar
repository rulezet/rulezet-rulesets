rule LZSS__N_4096__F_18__T_2___32_lil_AND_
{
strings:
	$a0 = { ee0f0000[0-20]f0000000[0-20]ff0f0000[0-20]ff0f0000 }

condition:
	$a0
}