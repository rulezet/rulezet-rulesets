rule Win_Trojan_Amz_1
{
strings:
	$a0 = { 0143bac104cd21c32ef6062704019074078ed0531e1eeb05501e068cc88ec08ed80631c08ec0268b1e6c04891e }


condition:
	$a0
}