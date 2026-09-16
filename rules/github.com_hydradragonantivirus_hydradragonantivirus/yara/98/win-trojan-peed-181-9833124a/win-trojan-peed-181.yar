rule Win_Trojan_Peed_181
{
strings:
	$a0 = { f7d987f37558ba0400000087d181c46b08000081ec670800006866f80100ff15 }


condition:
	$a0
}