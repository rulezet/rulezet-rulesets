rule GSM_A5_2_goodAtoB__8_byt_15_
{
strings:
	$a0 = { f4512cac13593764460b722dadd500 }

condition:
	$a0
}