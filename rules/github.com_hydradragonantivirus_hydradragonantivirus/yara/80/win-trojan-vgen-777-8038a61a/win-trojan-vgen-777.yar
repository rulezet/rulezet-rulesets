rule Win_Trojan_VGEN_777
{
strings:
	$a0 = { e800005d83ed10b42acd2181f9c9077707725480fe0a724fb8addecd213daaaa7445b82135cd212e899e86002e8c86 }


condition:
	$a0
}