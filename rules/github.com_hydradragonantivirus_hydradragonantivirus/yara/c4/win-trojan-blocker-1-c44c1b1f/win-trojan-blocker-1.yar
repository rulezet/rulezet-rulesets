rule Win_Trojan_Blocker_1
{
strings:
	$a0 = { 313862623139396300 }


condition:
	$a0
}