rule Win_Trojan_HDKiller_2
{
strings:
	$a0 = { d8ff061304581f9dfbcfb404cd1a2e3a1654007538ba80ffb90100bbaa00fec6b81103cd13 }


condition:
	$a0
}