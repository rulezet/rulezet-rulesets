rule Win_Trojan_ACRV_1
{
strings:
	$a0 = { 48018b941601b9bc008b0733c286e033c286e0890783c302e2ef5bc3 }


condition:
	$a0
}