rule Win_Trojan_MINY_1
{
strings:
	$a0 = { 01e82200fe8657015a5983c91fb8481ee81300b477e80e00c333c933d2b440fec4fec4cd21 }


condition:
	$a0
}