rule Zlib_base_length__8_byt_29_
{
strings:
	$a0 = { 0001020304050607080a0c0e1014181c202830384050607080a0c0e000 }

condition:
	$a0
}