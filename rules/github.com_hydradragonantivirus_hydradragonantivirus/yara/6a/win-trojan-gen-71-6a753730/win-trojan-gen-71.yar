rule Win_Trojan_Gen_71
{
strings:
	$a0 = { c6030101c6b904008cc88ec08ed8bf }


condition:
	$a0
}