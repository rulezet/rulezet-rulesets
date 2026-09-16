rule Win_Trojan_Zol_2
{
strings:
	$a0 = { 01978a952a2e636f6d00e96100cd2000a0009af0fe1df0dc0198144b0198145601981498140101010002ffffffff }


condition:
	$a0
}