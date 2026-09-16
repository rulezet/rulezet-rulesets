rule Win_Trojan_Tonester_1
{
strings:
	$a0 = { 5056e84d0f83c40a4683fe0a76e4b8f90050e88aff59b8050150e8380559b8270150e83005 }


condition:
	$a0
}