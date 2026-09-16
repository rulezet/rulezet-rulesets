rule Win_Trojan_Sality_1020
{
strings:
	$a0 = { 60e8550000008dbd0010400068??????00033c248bf79068311040009bdbe3 }


condition:
	$a0
}