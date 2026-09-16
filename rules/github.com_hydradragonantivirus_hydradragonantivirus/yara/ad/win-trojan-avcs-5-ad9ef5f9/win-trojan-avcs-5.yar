rule Win_Trojan_AVCS_5
{
strings:
	$a0 = { 8db60901bf4df9b90d01f3a4be71f9e85bffb440ba4df9b90d01cd21b80042e81c00b440b903 }


condition:
	$a0
}