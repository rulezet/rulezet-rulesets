rule Win_Trojan_Wildy_4
{
strings:
	$a0 = { cd213c05751780fd127512b80013bd3902bb8c00ba160db9220090cd1006cd12b106d3e08ec026803e5b02577442 }


condition:
	$a0
}