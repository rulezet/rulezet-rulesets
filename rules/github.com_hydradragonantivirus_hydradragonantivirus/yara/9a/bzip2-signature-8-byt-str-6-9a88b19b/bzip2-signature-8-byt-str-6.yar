rule Bzip2_signature__8_byt_STR_6_
{
strings:
	$a0 = { 425a68393141 }

condition:
	$a0
}