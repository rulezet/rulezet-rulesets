rule LZMA_compression__8_byt_24_
{
strings:
	$a0 = { 000000000102030405060405070707070707070a0a0a0a0a }

condition:
	$a0
}