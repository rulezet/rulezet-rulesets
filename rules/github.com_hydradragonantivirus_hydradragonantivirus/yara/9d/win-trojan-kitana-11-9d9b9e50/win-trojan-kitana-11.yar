rule Win_Trojan_Kitana_11
{
strings:
	$a0 = { 03cd13803f85740cc747fe55aab80203b701cd13c30e1fff0e1304cd12c1e0068ec033ff }


condition:
	$a0
}