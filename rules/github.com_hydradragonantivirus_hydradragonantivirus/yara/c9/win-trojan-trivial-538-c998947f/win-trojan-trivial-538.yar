rule Win_Trojan_Trivial_538
{
strings:
	$a0 = { b44e5acd2183ea??b43ccd2193b440b1??5acd21c3 }


condition:
	$a0
}