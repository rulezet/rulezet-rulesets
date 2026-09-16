rule Win_Trojan_VGEN_304
{
strings:
	$a0 = { b44ebab601cd217203e98c00b42acd2181f9cd07720a80fe0b750580fa02741bb42ccd210ad27511c606ca0124b4 }


condition:
	$a0
}