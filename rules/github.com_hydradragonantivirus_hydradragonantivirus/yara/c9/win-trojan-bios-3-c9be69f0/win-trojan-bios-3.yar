rule Win_Trojan_Bios_3
{
strings:
	$a0 = { b90100bb0009b801020e0e071fcd13515253b900018b0743433107e2f95b5a59b80103cd13c3 }


condition:
	$a0
}