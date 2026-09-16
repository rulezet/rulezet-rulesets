rule Ruby_MARK_5__32_big_AND_
{
strings:
	$a0 = { 456c6091[0-20]aa7110c3[0-20]0000001f[0-20]0000001b }

condition:
	$a0
}