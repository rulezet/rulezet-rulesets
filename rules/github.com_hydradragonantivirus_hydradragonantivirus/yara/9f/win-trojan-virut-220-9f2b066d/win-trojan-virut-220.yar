rule Win_Trojan_Virut_220
{
strings:
	$a0 = { fce81f000000b9d10d0000538bda6631104086d6408d1413e2f45bc35d0f31 }


condition:
	$a0
}