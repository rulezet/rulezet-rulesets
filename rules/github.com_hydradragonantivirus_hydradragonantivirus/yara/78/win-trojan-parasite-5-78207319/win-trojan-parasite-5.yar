rule Win_Trojan_Parasite_5
{
strings:
	$a0 = { 0189860401b440b971018d96000152cd21b8004233c933d2cd21b440b904005acd21b80157 }


condition:
	$a0
}