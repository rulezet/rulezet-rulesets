rule Win_Trojan_VCL_MUT_2
{
strings:
	$a0 = { b9030051e8080059e2f9b8004ccd21558bec83ec40b44732d28d76c0cd21ba3f01e81d00b43bba3c01cd2173 }


condition:
	$a0
}