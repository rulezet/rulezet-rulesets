rule GSM_table_gsm_NRFAC__16_lil_16_
{
strings:
	$a0 = { c8716766185d5655c54e254944440040 }

condition:
	$a0
}