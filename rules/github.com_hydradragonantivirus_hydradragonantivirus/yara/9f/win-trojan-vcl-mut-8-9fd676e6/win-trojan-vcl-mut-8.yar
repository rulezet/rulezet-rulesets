rule Win_Trojan_VCL_MUT_8
{
strings:
	$a0 = { 9090b9030051e8080059e2f9b8004ccd21558bec83ec40b44732d28d76c0cd21b43bba3701cd21e80d00b43b8d56 }


condition:
	$a0
}