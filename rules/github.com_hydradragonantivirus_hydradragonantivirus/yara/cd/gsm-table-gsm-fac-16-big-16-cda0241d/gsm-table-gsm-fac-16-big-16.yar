rule GSM_table_gsm_FAC__16_big_16_
{
strings:
	$a0 = { 47ff4fff57ff5fff67ff6fff77ff7fff }

condition:
	$a0
}