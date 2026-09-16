rule TNS_filter_short_SSR_tnsMaxBandsShort__8_byt_12_
{
strings:
	$a0 = { 070707060606070708080807 }

condition:
	$a0
}