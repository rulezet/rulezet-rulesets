rule Win_Trojan_VGEN_640
{
strings:
	$a0 = { 7742cd217343b44abbffffcd21b44a83eb11cd21b448bb1000cd212d10008ec0bf03018bf48b3483ee03b9e900f3a4 }


condition:
	$a0
}