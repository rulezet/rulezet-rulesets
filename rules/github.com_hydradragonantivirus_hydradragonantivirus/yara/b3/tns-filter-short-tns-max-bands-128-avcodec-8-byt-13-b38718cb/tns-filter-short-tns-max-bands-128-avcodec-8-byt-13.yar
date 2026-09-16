rule TNS_filter_short_tns_max_bands_128__avcodec___8_byt_13_
{
strings:
	$a0 = { 09090a0e0e0e0e0e0e0e0e0e0e }

condition:
	$a0
}