rule Win_Trojan_Arcs_1
{
strings:
	$a0 = { 8b0f83e90381c1aa008bd8894f015b5381eba9008b1fb90300b4405a5281eab200cd215b }


condition:
	$a0
}