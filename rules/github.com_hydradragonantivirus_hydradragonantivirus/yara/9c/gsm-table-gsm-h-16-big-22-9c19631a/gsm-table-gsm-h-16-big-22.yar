rule GSM_table_gsm_H__16_big_22_
{
strings:
	$a0 = { FF7AFE8A00000806166D2000166D08060000FE8AFF7A }

condition:
	$a0
}