rule Win_Trojan_C_317
{
strings:
	$a0 = { 6801204b00e801000000c3c37dac4ea52478f58940bbdccd2cff7f2148257930 }


condition:
	$a0
}