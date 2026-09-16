rule Win_Trojan_Flood_16
{
strings:
	$a0 = { 5c004500740068004400720076 }

	$a1 = { 4574686572466c6f6f64 }


condition:
	$a0 and $a1
}