rule Win_Trojan_VCL_MUT_7
{
strings:
	$a0 = { 92e80800e80500b8004ccd21558bec83ec40b44732d28d76c0cd21b43bba3301cd21e80d00b43b8d56c0cd218b }


condition:
	$a0
}