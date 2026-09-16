rule Win_Trojan_SillyORC_11
{
strings:
	$a0 = { 0389160b03890e0f0353b82012cd2fb81612268a1dcd2f5b26817d28434f755e26c745020200 }


condition:
	$a0
}