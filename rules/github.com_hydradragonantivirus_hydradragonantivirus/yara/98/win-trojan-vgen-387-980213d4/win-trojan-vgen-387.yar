rule Win_Trojan_VGEN_387
{
strings:
	$a0 = { e80300cd2090b87742cd217343b44abbffffcd21b44a83eb12cd21b448bb1100cd212d10008ec0bf03018bf48b3483ee }


condition:
	$a0
}