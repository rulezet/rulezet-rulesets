rule Win_Trojan_Born2Loose_2
{
strings:
	$a0 = { c1b0048bfe81efab03890db9ca038bd681eab003b440cd21722133c933d2b8420086e0cd217214 }


condition:
	$a0
}