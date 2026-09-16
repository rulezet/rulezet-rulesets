rule Win_Trojan_Peed_241
{
strings:
	$a0 = { 3cf381ce2e7b6500b88002460081e22e7c06016869507402c1eb2145f7d3f35bbbe2084f0056558bde5df7d333dc5bc1 }


condition:
	$a0
}