rule Win_Trojan_Packed_125
{
strings:
	$a0 = { be5b2a4000bf35120000 }

	$a1 = { 5333c9498bd133c033dbac32c18acd8aea8ad6b60866d1eb66d1d87309663520836681f3b8edfece75eb33c833d34f75d5f7d2f7d15b8bc2c1c010668bc1c3 }


condition:
	$a0 and $a1
}