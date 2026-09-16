rule Win_Trojan_Birgit_49
{
strings:
	$a0 = { b80043cc890e????b8014333c9ccb8023dcc93b80057cc5152b43fba????b90400cc803e????ea74 }


condition:
	$a0
}