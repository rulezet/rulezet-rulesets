rule GSM_table_gsm_A__16_lil_16_
{
strings:
	$a0 = { 00500050005000508c36003c56214c23 }

condition:
	$a0
}