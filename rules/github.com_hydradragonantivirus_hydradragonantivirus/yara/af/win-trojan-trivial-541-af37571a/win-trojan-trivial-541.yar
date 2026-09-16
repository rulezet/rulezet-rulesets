rule Win_Trojan_Trivial_541
{
strings:
	$a0 = { b44ecd21ba????b8013dcd2193b440b1??5acd21c3 }


condition:
	$a0
}