rule Win_Trojan_N_47
{
strings:
	$a0 = { 8ec08ed8bb007cfa8ed08be3fb5053bf0006508d752490568bf3b9750090 }


condition:
	$a0
}