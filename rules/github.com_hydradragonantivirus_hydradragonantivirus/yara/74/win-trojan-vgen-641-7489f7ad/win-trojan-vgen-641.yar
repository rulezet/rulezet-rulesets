rule Win_Trojan_VGEN_641
{
strings:
	$a0 = { 42cd217343b44abbffffcd21b44a83eb12cd21b448bb1100cd212d10008ec0bf03018bf48b3483ee03b9ef00f3a4 }


condition:
	$a0
}