rule Win_Trojan_VGEN_385
{
strings:
	$a0 = { 0300cd2090b87742cd217343b44abbffffcd21b44a83eb11cd21b448bb1000cd212d10008ec0bf03018bf48b3483ee }


condition:
	$a0
}