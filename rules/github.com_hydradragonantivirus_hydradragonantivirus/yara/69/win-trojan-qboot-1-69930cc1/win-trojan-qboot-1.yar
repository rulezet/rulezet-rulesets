rule Win_Trojan_Qboot_1
{
strings:
	$a0 = { 1304802e130403b90600d3e02d00108ec0b80302bb00f6b90300ba8000cd13722bbfd6f8be4c00 }


condition:
	$a0
}