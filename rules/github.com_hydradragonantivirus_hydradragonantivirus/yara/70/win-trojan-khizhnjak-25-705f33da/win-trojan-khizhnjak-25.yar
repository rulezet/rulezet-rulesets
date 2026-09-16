rule Win_Trojan_Khizhnjak_25
{
strings:
	$a0 = { 028826bf02b900008b16b9028b1ebb02b80042cd21723aba1001b9b602908b1ebb02b440cd21 }


condition:
	$a0
}