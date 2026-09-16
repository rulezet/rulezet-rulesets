rule Win_Trojan_Xuxa_8
{
strings:
	$a0 = { b63e008d862a00e3120e502e31142ed20446fec249cbfb }


condition:
	$a0
}