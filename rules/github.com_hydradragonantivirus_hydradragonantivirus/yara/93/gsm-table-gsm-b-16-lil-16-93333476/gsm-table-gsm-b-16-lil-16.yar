rule GSM_table_gsm_B__16_lil_16_
{
strings:
	$a0 = { 00000000000800F65E0000F9ABFE88FB }

condition:
	$a0
}