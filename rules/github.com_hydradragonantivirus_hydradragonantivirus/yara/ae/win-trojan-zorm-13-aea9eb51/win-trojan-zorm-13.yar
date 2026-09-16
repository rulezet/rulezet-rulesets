rule Win_Trojan_Zorm_13
{
strings:
	$a0 = { b000b90b001e521fb43efecccd2104021fbb1d00e86302 }


condition:
	$a0
}