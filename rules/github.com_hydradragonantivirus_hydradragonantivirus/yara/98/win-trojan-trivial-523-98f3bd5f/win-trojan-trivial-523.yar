rule Win_Trojan_Trivial_523
{
strings:
	$a0 = { 2a2e2a00b44e8bd6cd21ba9e0066391e9a007504b441cd21b44fcd2173efc3 }


condition:
	$a0
}