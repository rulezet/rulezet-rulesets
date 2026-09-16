rule Win_Trojan_Razer_1
{
strings:
	$a0 = { 010300558e0100000001005e030000b603000003000000250a }


condition:
	$a0
}