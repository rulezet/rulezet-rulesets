rule Win_Trojan_VGEN_453
{
strings:
	$a0 = { 0ee8c5013d05007506b90300e89c0132e4cd1af7c201007503e83100e8a2013d0b00750fe8 }


condition:
	$a0
}