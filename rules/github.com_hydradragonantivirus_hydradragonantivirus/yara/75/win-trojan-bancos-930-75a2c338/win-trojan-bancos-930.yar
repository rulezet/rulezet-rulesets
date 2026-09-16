rule Win_Trojan_Bancos_930
{
strings:
	$a0 = { 139b0638964adc4c97c6fabb722a7c6139205fe1ba1b1320da80f8307dcca04daea1bbec9d3beec72a3891c1843d5bdcfb52429ccdda6fbb99d48d4596fbb70c }


condition:
	$a0
}