rule Win_Trojan_Haze_2
{
strings:
	$a0 = { 919d8507679aa93a3306854266b011d3457968970471a25beeed94cdf6fc0274cfff4059cb122476 }


condition:
	$a0
}