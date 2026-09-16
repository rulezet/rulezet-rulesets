rule GSM_table_gsm_A__16_big_16_
{
strings:
	$a0 = { 5000500050005000368c3c002156234c }

condition:
	$a0
}