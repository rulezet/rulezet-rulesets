rule Win_Trojan_Trivial_530
{
strings:
	$a0 = { b44ecd21ba????b43dcd2193b213 }


condition:
	$a0
}