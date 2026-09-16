rule Win_Trojan_Anni_5
{
strings:
	$a0 = { 301743e2fb0d1af7612e1af5611b1a0b19f0f170ac195bf3701cd1f1eff74997c13cd0ccbebf85a34a0e0e45bb }


condition:
	$a0
}