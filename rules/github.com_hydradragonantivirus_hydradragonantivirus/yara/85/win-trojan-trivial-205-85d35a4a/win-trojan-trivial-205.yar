rule Win_Trojan_Trivial_205
{
strings:
	$a0 = { b44ecd21ba9e00b8023dcd2193ba0001b92600b440cd21b43ecd21b44f }


condition:
	$a0
}