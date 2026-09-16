rule GSM_table_gsm_INVA__16_big_16_
{
strings:
	$a0 = { 33333333333333334b1744447ade740c }

condition:
	$a0
}