rule EC_curve__EC_SECG_CHAR2_131R1_SEED__8_byt_20_
{
strings:
	$a0 = { 4d696e676875615175985bd3adbada21b43a97e2 }

condition:
	$a0
}