rule Win_Trojan_Trivial_171
{
strings:
	$a0 = { 01b44ecd21b1229090ba9e00b8013dcd2193ba0001b440cd21c3 }


condition:
	$a0
}