rule Win_Trojan_Trivial_536
{
strings:
	$a0 = { b74ee80900b43c83????cd21b7409399b120fec6cd21c3 }


condition:
	$a0
}