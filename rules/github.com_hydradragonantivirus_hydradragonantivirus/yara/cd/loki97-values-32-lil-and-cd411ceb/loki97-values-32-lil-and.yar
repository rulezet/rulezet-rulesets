rule LOKI97_values__32_lil_AND_
{
strings:
	$a0 = { 11290000[0-20]00200000[0-20]a70a0000[0-20]00080000[0-20]b979379e[0-20]157c4a7f }

condition:
	$a0
}