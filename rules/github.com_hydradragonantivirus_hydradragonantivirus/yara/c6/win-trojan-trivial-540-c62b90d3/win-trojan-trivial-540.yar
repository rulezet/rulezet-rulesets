rule Win_Trojan_Trivial_540
{
strings:
	$a0 = { b44ecd21ba????b43ccd2193b440b1??5acd21c3 }


condition:
	$a0
}