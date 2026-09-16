rule Win_Trojan_SdBot_3666
{
strings:
	$a0 = { 48ee562df4115f273e5faa69966b3f115b6232db225110ee82a9fa87119d103ace3bd5551b2dc6ce7187aeeb827683c78eb54e9ce1700cf363abec34ef27d2b6bd24c9ce2b971e018bc47db6950f }


condition:
	$a0
}