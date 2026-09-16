rule Win_Trojan_Mockoder_1
{
strings:
	$a0 = { c560040000bb3480112e8db5c4fbffff8bfeb90f010000adf7d0d3c033c3abe2f6 }


condition:
	$a0
}