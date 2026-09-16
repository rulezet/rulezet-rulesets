rule Win_Trojan_Hancitor_2
{
strings:
	$a0 = { e886350000e989feffff8bff558bec83ec208b450856576a08 }


condition:
	$a0
}