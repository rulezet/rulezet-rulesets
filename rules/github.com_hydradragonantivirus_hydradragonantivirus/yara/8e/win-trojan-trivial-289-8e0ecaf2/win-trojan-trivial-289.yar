rule Win_Trojan_Trivial_289
{
strings:
	$a0 = { 01b44ecd21721eba9e00b8013dcd218bd8b440b92f00ba0001cd21b43ecd21b44fcd21ebe0cd20 }


condition:
	$a0
}