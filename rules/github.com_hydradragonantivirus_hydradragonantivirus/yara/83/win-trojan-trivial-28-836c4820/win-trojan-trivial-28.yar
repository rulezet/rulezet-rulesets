rule Win_Trojan_Trivial_28
{
strings:
	$a0 = { 9e005052cd2193b43f5459d1e2cd215a03c2935839444a740acd2193918bd6b440cd21b44febd1 }


condition:
	$a0
}