rule Win_Trojan_Trivial_138
{
strings:
	$a0 = { ba2201b44ecd21ba9e00b43ccd2193b440ba0001b128cd21b80200cd24cd20 }


condition:
	$a0
}