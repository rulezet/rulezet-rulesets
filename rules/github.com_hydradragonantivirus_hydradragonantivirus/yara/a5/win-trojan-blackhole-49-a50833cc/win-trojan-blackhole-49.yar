rule Win_Trojan_Blackhole_49
{
strings:
	$a0 = { 226576222b22616c225d3b7d6361746368287a786329 }


condition:
	$a0
}