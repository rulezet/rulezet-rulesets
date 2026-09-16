rule Win_Trojan_Dieg_1
{
strings:
	$a0 = { 0690ba0001b440cd21722b2e8b1682012e8b0e8401b8 }


condition:
	$a0
}