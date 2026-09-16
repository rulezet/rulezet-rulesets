rule Win_Trojan_Trivial_353
{
strings:
	$a0 = { 01b92000b44ecd217220ba9e00b8013dcd218bd8b94d00ba0001b440cd21720ab43ecd21b44f }


condition:
	$a0
}