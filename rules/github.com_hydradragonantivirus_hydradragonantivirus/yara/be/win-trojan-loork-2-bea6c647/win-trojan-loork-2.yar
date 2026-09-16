rule Win_Trojan_Loork_2
{
strings:
	$a0 = { 6b7230306c2e }

	$a1 = { 206279205b77617267616d652c23656f665d }

	$a2 = { 7768696c652828667070707070203d206469727272722e }


condition:
	$a0 and $a1 and $a2
}