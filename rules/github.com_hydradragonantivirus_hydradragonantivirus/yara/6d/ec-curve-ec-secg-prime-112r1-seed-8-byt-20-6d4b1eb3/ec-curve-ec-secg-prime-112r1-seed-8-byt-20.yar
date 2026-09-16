rule EC_curve__EC_SECG_PRIME_112R1_SEED__8_byt_20_
{
strings:
	$a0 = { 00f50b028e4d696e676875615175290472783fb1 }

condition:
	$a0
}