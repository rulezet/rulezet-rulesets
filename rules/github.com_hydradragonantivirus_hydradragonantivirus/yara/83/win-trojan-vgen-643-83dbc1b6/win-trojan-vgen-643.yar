rule Win_Trojan_VGEN_643
{
strings:
	$a0 = { 42cd217333b44abbffffcd21b44a83eb1ccd21b448bb1b00cd212d10008ec0bf03018bf48b3483ee03b99901f3a4 }


condition:
	$a0
}