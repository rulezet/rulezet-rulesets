rule Win_Trojan_VGEN_661
{
strings:
	$a0 = { 020000e80300e9e80051b96103be37018bfefcad33060201ab49e302ebf559c3ba00018b1ee601b92a02e8dcffb800 }


condition:
	$a0
}