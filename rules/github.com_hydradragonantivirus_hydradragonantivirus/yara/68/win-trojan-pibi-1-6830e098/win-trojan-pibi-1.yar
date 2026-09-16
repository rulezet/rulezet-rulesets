rule Win_Trojan_Pibi_1
{
strings:
	$a0 = { 68c08b0408e8cafbffff83c4046a028b45fc50e85cfbffff83c4088b45fc50e830fbffff83c4048b5dd4c9c3 }

	$a1 = { 7269636b2d6173732d62697463 }


condition:
	$a0 and $a1
}