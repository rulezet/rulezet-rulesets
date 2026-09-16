rule Win_Trojan_Ascii_183_60_201_227_1
{
strings:
	$a0 = { 3138332e36302e3230312e323237 }


condition:
	$a0
}