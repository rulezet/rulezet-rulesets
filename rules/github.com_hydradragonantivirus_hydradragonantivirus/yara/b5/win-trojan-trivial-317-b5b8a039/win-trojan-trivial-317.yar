rule Win_Trojan_Trivial_317
{
strings:
	$a0 = { ba3201b44ecd21ba9e00b8023dcd21b8004233c933d2cd2172e48bd8ba0001b138b440cd21b43ecd }


condition:
	$a0
}