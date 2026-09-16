rule Win_Trojan_Butt_3
{
strings:
	$a0 = { 508d9ec202b95a008ab6c1028a2732e6882743e2f7585b595ac3 }


condition:
	$a0
}