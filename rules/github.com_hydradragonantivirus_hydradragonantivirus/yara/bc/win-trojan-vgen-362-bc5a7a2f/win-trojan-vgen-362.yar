rule Win_Trojan_VGEN_362
{
strings:
	$a0 = { 01e88a0133c9b11451ba4701b43c33c9cd2193beff01bf830bb9a000e85c09b440ba830bcd21b43ecd21a14c01 }


condition:
	$a0
}