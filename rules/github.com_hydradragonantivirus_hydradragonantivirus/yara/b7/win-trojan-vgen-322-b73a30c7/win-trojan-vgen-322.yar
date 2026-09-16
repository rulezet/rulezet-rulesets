rule Win_Trojan_VGEN_322
{
strings:
	$a0 = { ba9802cd2193b43fb9000151bab006cd2159813eb2062d6c7518beb0068dbc0001f3a4e8a800bdb0078b460f24 }


condition:
	$a0
}