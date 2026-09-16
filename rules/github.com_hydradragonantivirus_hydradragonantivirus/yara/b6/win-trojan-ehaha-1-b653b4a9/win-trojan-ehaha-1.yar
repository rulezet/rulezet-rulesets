rule Win_Trojan_Ehaha_1
{
strings:
	$a0 = { bf52001e57b8000250b046509aa7071900bf5c031e57bf78000e5731c0509a700619009add051900 }


condition:
	$a0
}