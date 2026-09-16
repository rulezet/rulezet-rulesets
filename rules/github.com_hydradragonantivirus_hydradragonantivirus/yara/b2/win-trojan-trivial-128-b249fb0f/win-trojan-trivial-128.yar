rule Win_Trojan_Trivial_128
{
strings:
	$a0 = { 3000b800008bd8e67093e67193050100e2f5b00ae670b026e647cd20 }


condition:
	$a0
}