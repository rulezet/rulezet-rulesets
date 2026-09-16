rule GSM_table_gsm_INVA__16_lil_16_
{
strings:
	$a0 = { 3333333333333333174b4444de7a0c74 }

condition:
	$a0
}