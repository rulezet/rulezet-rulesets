rule Lucifer__outerbridge__DFLTKY__8_byt_16_
{
strings:
	$a0 = { 0123456789abcdeffedcba9876543210 }

condition:
	$a0
}