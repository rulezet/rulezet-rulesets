rule Win_Trojan_VGEN_427
{
strings:
	$a0 = { 038bdc83c30fb104d3ebb44acd21bf2c01be0d01b90c00f3a4ba03018b0e2701b44ecd217279bf0d01be9e00b90c }


condition:
	$a0
}