rule Win_Trojan_Trivial_216
{
strings:
	$a0 = { 2701b44ecd21ba9e00b8023dcd218bd8ba0001b127b440cd21b43ecd21b44fcd2173e3c3 }


condition:
	$a0
}