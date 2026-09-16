rule Win_Trojan_Dexter_1
{
strings:
	$a0 = { 2e6578659a000095009a0d0033005589e5b800019acd02950081ec0001bf00000e57b83f0050bf }


condition:
	$a0
}