rule EC_curve__EC_SECG_CHAR2_113R1_SEED__8_byt_20_
{
strings:
	$a0 = { 10e723ab14d696e6768756151756febf8fcb49a9 }

condition:
	$a0
}