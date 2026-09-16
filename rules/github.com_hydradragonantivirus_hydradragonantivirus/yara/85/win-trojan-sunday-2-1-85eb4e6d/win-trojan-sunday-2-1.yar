rule Win_Trojan_Sunday_2_1
{
strings:
	$a0 = { e800005e81ee03008beefc5006561eb42acd213c007502eb03e9c901b401b92020cd10b40233d2cd1033c0cd10b40eb049cd10b40eb074cd10b40eb027cd10b40eb073 }


condition:
	$a0
}