rule Win_Trojan_Dikshev_19
{
strings:
	$a0 = { 2e652ab44eb99e0087ce99fec6cd217301c3b22987d6afb02ef2ae66a5b45bcd21720393b440eb }


condition:
	$a0
}