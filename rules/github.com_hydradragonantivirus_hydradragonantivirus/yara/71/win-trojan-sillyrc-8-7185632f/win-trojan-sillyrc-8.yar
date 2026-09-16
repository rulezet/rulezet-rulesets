rule Win_Trojan_SillyRC_8
{
strings:
	$a0 = { 3d4d5a741d813dbf007417b002e8b2ffa30303b440cde832c0e8a6ff03d1b440cde8b43ecde81f }


condition:
	$a0
}