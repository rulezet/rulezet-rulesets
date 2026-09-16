rule Win_Trojan_Trivial_282
{
strings:
	$a0 = { 33c9ba2701b44ecd21ba9e00b8023dcd218bd8ba0001b12db440cd21b43ecd21b44fcd2173e3c3 }


condition:
	$a0
}