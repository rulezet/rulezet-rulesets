rule Win_Trojan_Trivial_197
{
strings:
	$a0 = { 2101b44ecd217217ba9e00b8013dcd2193b440b92500ba0001cd21b43ecd21c3 }


condition:
	$a0
}