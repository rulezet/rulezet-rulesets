rule Win_Trojan_Subliminal_1
{
strings:
	$a0 = { 01b821250e1fbaa501cd212e8e062c00 }


condition:
	$a0
}