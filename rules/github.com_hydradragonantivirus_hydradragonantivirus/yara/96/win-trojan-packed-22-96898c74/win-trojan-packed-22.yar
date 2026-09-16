rule Win_Trojan_Packed_22
{
strings:
	$a0 = { 6801002513e801000000c3c3 }


condition:
	$a0
}