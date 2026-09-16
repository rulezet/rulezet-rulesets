rule Win_Trojan_L_31
{
strings:
	$a0 = { 5d10e80300e9f40051eb0190b91f04eb0190be4401eb01908bfeeb0190fcad33060301ab49e302ebf559 }


condition:
	$a0
}