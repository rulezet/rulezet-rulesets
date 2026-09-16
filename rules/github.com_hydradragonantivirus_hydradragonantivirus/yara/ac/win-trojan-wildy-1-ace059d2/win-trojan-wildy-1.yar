rule Win_Trojan_Wildy_1
{
strings:
	$a0 = { 06d3e08ec026803e2f025790902d40008ec0bf00018bf7b9620190f3a48cc11e33c08ed850be8400bf5a01a5a5 }


condition:
	$a0
}