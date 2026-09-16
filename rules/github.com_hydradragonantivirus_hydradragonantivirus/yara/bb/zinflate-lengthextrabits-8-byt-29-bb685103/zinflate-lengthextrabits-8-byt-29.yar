rule zinflate_lengthExtraBits__8_byt_29_
{
strings:
	$a0 = { 0000000000000000010101010202020203030303040404040505050500 }

condition:
	$a0
}